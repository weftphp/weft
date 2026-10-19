/*
 * Thin glue between the Zend engine and the Rust crate.
 *
 * Everything here is mechanical: macros and inline helpers that Rust cannot call, runtime
 * construction of function/class tables, and the per-coroutine swap of executor state. All
 * behaviour lives in Rust and is reached through the `weft_rs_*` callbacks and the handler
 * pointers it registers.
 */

#include "php.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"

#ifdef ZTS
#error "weft supports non-thread-safe (NTS) PHP builds only"
#endif

#include <stdlib.h>
#include <string.h>

typedef void (*weft_fn)(void *execute_data, void *return_value);

extern int weft_rs_minit(void);
extern void weft_rs_rshutdown(void);

/* ---------------------------------------------------------------- exceptions */

static zend_class_entry *weft_ce_exception;
static zend_object *weft_stashed_exception;

void weft_throw(const char *message, long code)
{
	zend_throw_exception(weft_ce_exception, message, code);
}

int weft_exception_pending(void)
{
	return EG(exception) != NULL;
}

/* Moves a pending exception aside so a coroutine can finish; the first one wins. */
void weft_exception_stash(void)
{
	zend_object *ex = EG(exception);
	if (ex == NULL) {
		return;
	}
	GC_ADDREF(ex);
	zend_clear_exception();
	if (weft_stashed_exception == NULL) {
		weft_stashed_exception = ex;
	} else {
		OBJ_RELEASE(ex);
	}
}

/* Prints a pending exception as an uncaught-exception warning and clears it. */
void weft_exception_report(void)
{
	zend_object *ex = EG(exception);
	if (ex == NULL) {
		return;
	}
	GC_ADDREF(ex);
	zend_clear_exception();
	zend_exception_error(ex, E_WARNING);
}

int weft_exception_stashed(void)
{
	return weft_stashed_exception != NULL;
}

/* Rethrows the stashed exception in the current (main) context. */
void weft_exception_rethrow(void)
{
	zval zv;
	if (weft_stashed_exception == NULL) {
		return;
	}
	ZVAL_OBJ(&zv, weft_stashed_exception);
	weft_stashed_exception = NULL;
	zend_throw_exception_object(&zv);
}

/* ------------------------------------------------------------------- objects */

typedef struct {
	void *ptr;
	void (*dtor)(void *);
	zend_object std;
} weft_obj;

typedef struct {
	char *name;
	zend_function_entry *entries;
	size_t count;
	size_t capacity;
	zend_class_entry *ce;
} weft_class;

static zend_object_handlers weft_handlers;

static weft_obj *weft_obj_from(zend_object *o)
{
	return (weft_obj *) ((char *) o - XtOffsetOf(weft_obj, std));
}

static zend_object *weft_create(zend_class_entry *ce)
{
	weft_obj *o = zend_object_alloc(sizeof(weft_obj), ce);
	zend_object_std_init(&o->std, ce);
	object_properties_init(&o->std, ce);
	o->std.handlers = &weft_handlers;
	return &o->std;
}

static void weft_free(zend_object *zo)
{
	weft_obj *o = weft_obj_from(zo);
	if (o->ptr != NULL && o->dtor != NULL) {
		void *p = o->ptr;
		o->ptr = NULL;
		o->dtor(p);
	}
	zend_object_std_dtor(zo);
}

void *weft_this_ptr(void *ed)
{
	zend_execute_data *e = ed;
	if (Z_TYPE(e->This) != IS_OBJECT) {
		return NULL;
	}
	return weft_obj_from(Z_OBJ(e->This))->ptr;
}

void weft_this_set(void *ed, void *ptr, void (*dtor)(void *))
{
	zend_execute_data *e = ed;
	weft_obj *o = weft_obj_from(Z_OBJ(e->This));
	o->ptr = ptr;
	o->dtor = dtor;
}

void *weft_class_new(const char *name)
{
	weft_class *c = calloc(1, sizeof(*c));
	c->name = strdup(name);
	c->capacity = 8;
	c->entries = calloc(c->capacity + 1, sizeof(zend_function_entry));
	return c;
}

/* Builds internal arginfo: slot 0 is the return descriptor, then `total` untyped arguments. */
static zend_internal_arg_info *weft_arginfo(uint32_t required, uint32_t total, int variadic)
{
	zend_internal_arg_info *ai = calloc(total + 1, sizeof(*ai));
	ai[0].name = (const char *) (uintptr_t) required;
	for (uint32_t i = 0; i < total; i++) {
		char buf[16];
		snprintf(buf, sizeof(buf), "arg%u", i);
		ai[i + 1].name = strdup(buf);
		if (variadic && i + 1 == total) {
			ai[i + 1].type.type_mask = _ZEND_ARG_INFO_FLAGS(0, 1, 0);
		}
	}
	return ai;
}

int weft_class_method(void *h, const char *name, weft_fn fn, uint32_t required, uint32_t total,
		int variadic, int is_static)
{
	weft_class *c = h;
	if (c->count == c->capacity) {
		c->capacity *= 2;
		c->entries = realloc(c->entries, (c->capacity + 1) * sizeof(zend_function_entry));
		memset(&c->entries[c->count], 0, (c->capacity + 1 - c->count) * sizeof(zend_function_entry));
	}
	zend_function_entry *e = &c->entries[c->count++];
	e->fname = strdup(name);
	e->handler = (zif_handler) fn;
	e->arg_info = weft_arginfo(required, total, variadic);
	e->num_args = total;
	e->flags = ZEND_ACC_PUBLIC | (is_static ? ZEND_ACC_STATIC : 0);
	return 0;
}

int weft_class_register(void *h)
{
	weft_class *c = h;
	zend_class_entry ce;
	INIT_CLASS_ENTRY_EX(ce, c->name, strlen(c->name), c->entries);
	c->ce = zend_register_internal_class_ex(&ce, NULL);
	if (c->ce == NULL) {
		return -1;
	}
	c->ce->create_object = weft_create;
	c->ce->ce_flags |= ZEND_ACC_NO_DYNAMIC_PROPERTIES | ZEND_ACC_NOT_SERIALIZABLE;
	c->ce->default_object_handlers = &weft_handlers;
	return 0;
}

/* Creates an instance of the class in `rv`, owning `ptr`. */
void weft_object_init(void *h, void *rv, void *ptr, void (*dtor)(void *))
{
	weft_class *c = h;
	object_init_ex((zval *) rv, c->ce);
	weft_obj *o = weft_obj_from(Z_OBJ_P((zval *) rv));
	o->ptr = ptr;
	o->dtor = dtor;
}

/* ----------------------------------------------------------------- functions */

int weft_register_function(const char *name, weft_fn fn, uint32_t required, uint32_t total,
		int variadic)
{
	zend_function_entry *fe = calloc(2, sizeof(*fe));
	fe[0].fname = strdup(name);
	fe[0].handler = (zif_handler) fn;
	fe[0].arg_info = weft_arginfo(required, total, variadic);
	fe[0].num_args = total;
	return zend_register_functions(NULL, fe, NULL, MODULE_PERSISTENT) == SUCCESS ? 0 : -1;
}

/* ------------------------------------------------------------------ arguments */

uint32_t weft_argc(void *ed)
{
	return ZEND_CALL_NUM_ARGS((zend_execute_data *) ed);
}

void *weft_arg(void *ed, uint32_t i)
{
	zval *z = ZEND_CALL_ARG((zend_execute_data *) ed, i + 1);
	ZVAL_DEREF(z);
	return z;
}

void weft_wrong_argc(void *ed, uint32_t min, uint32_t max)
{
	zend_wrong_parameters_count_error(min, max);
	(void) ed;
}

int weft_zval_type(void *zv)
{
	return Z_TYPE_P((zval *) zv);
}

long weft_zval_long(void *zv)
{
	return zval_get_long((zval *) zv);
}

double weft_zval_double(void *zv)
{
	return zval_get_double((zval *) zv);
}

int weft_zval_bool(void *zv)
{
	return zend_is_true((zval *) zv);
}

const char *weft_zval_str(void *zv, size_t *len)
{
	zval *z = zv;
	if (Z_TYPE_P(z) != IS_STRING) {
		return NULL;
	}
	*len = Z_STRLEN_P(z);
	return Z_STRVAL_P(z);
}

int weft_zval_is_callable(void *zv)
{
	return zend_is_callable((zval *) zv, 0, NULL);
}

/* Heap-owned copy of a zval; pairs with weft_zval_release. */
void *weft_zval_box(void *zv)
{
	zval *z = malloc(sizeof(zval));
	ZVAL_COPY(z, (zval *) zv);
	return z;
}

void weft_zval_release(void *zv)
{
	zval_ptr_dtor((zval *) zv);
	free(zv);
}

/* Copies `*src` (a boxed or borrowed zval) into the return slot. */
void weft_ret_copy(void *rv, void *src)
{
	ZVAL_COPY((zval *) rv, (zval *) src);
}

size_t weft_zval_size(void)
{
	return sizeof(zval);
}

void weft_zval_copy_to(void *dst, void *src)
{
	ZVAL_COPY((zval *) dst, (zval *) src);
}

void weft_zval_dtor(void *zv)
{
	zval_ptr_dtor((zval *) zv);
}

void weft_zval_set_long(void *zv, long v)
{
	ZVAL_LONG((zval *) zv, v);
}

void weft_zval_set_str(void *zv, const char *p, size_t n)
{
	ZVAL_STRINGL((zval *) zv, p, n);
}

/* ------------------------------------------------------------------- returns */

void weft_ret_null(void *rv)
{
	ZVAL_NULL((zval *) rv);
}

void weft_ret_bool(void *rv, int v)
{
	ZVAL_BOOL((zval *) rv, v);
}

void weft_ret_long(void *rv, long v)
{
	ZVAL_LONG((zval *) rv, v);
}

void weft_ret_double(void *rv, double v)
{
	ZVAL_DOUBLE((zval *) rv, v);
}

void weft_ret_str(void *rv, const char *p, size_t n)
{
	ZVAL_STRINGL((zval *) rv, p, n);
}

void weft_ret_this(void *rv, void *ed)
{
	zend_execute_data *e = ed;
	ZVAL_OBJ_COPY((zval *) rv, Z_OBJ(e->This));
}

/* ------------------------------------------------------------------- arrays */

void weft_arr_init(void *zv)
{
	array_init((zval *) zv);
}

void weft_arr_set_str(void *arr, const char *key, size_t klen, const char *v, size_t vlen)
{
	add_assoc_stringl_ex((zval *) arr, key, klen, v, vlen);
}

void weft_arr_set_long(void *arr, const char *key, size_t klen, long v)
{
	add_assoc_long_ex((zval *) arr, key, klen, v);
}

void weft_arr_set_bool(void *arr, const char *key, size_t klen, int v)
{
	add_assoc_bool_ex((zval *) arr, key, klen, v);
}

void weft_arr_set_double(void *arr, const char *key, size_t klen, double v)
{
	add_assoc_double_ex((zval *) arr, key, klen, v);
}

void weft_arr_push_str(void *arr, const char *v, size_t vlen)
{
	add_next_index_stringl((zval *) arr, v, vlen);
}

/* Adds an empty array at `arr[key]` and returns it for filling. */
void *weft_arr_child(void *arr, const char *key, size_t klen)
{
	zval tmp;
	array_init(&tmp);
	return zend_hash_str_update(Z_ARRVAL_P((zval *) arr), key, klen, &tmp);
}

typedef void (*weft_each_fn)(void *ctx, const char *key, size_t klen, int is_str, long idx, void *val);

void weft_arr_each(void *zv, weft_each_fn cb, void *ctx)
{
	zval *z = zv;
	zend_string *key;
	zend_ulong idx;
	zval *val;
	if (Z_TYPE_P(z) != IS_ARRAY) {
		return;
	}
	ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(z), idx, key, val) {
		ZVAL_DEREF(val);
		if (key != NULL) {
			cb(ctx, ZSTR_VAL(key), ZSTR_LEN(key), 1, 0, val);
		} else {
			cb(ctx, NULL, 0, 0, (long) idx, val);
		}
	} ZEND_HASH_FOREACH_END();
}

size_t weft_arr_count(void *zv)
{
	zval *z = zv;
	return Z_TYPE_P(z) == IS_ARRAY ? zend_hash_num_elements(Z_ARRVAL_P(z)) : 0;
}

/* ------------------------------------------------------------------ callables */

typedef struct {
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	zval fn;
} weft_callable;

void *weft_callable_new(void *zv)
{
	weft_callable *c = calloc(1, sizeof(*c));
	char *err = NULL;
	if (zend_fcall_info_init((zval *) zv, 0, &c->fci, &c->fcc, NULL, &err) != SUCCESS) {
		if (err != NULL) {
			efree(err);
		}
		free(c);
		return NULL;
	}
	ZVAL_COPY(&c->fn, (zval *) zv);
	c->fci.function_name = c->fn;
	return c;
}

void weft_callable_free(void *p)
{
	weft_callable *c = p;
	zval_ptr_dtor(&c->fn);
	free(c);
}

/* Calls with `argc` consecutive zvals at `argv`; `ret` receives the result (or stays UNDEF). */
int weft_callable_call(void *p, uint32_t argc, void *argv, void *ret)
{
	weft_callable *c = p;
	ZVAL_UNDEF((zval *) ret);
	c->fci.params = argv;
	c->fci.param_count = argc;
	c->fci.retval = ret;
	c->fci.named_params = NULL;
	return zend_call_function(&c->fci, &c->fcc) == SUCCESS ? 0 : -1;
}

/* ---------------------------------------------------------------- vm switching */

typedef struct {
	zend_vm_stack vm_stack;
	zval *vm_stack_top;
	zval *vm_stack_end;
	size_t vm_stack_page_size;
	zend_execute_data *current_execute_data;
	zend_object *exception;
	zend_object *prev_exception;
	const zend_op *opline_before_exception;
	zend_error_handling_t error_handling;
	zend_class_entry *exception_class;
	uint32_t jit_trace_num;
	void *stack_base;
	void *stack_limit;
} weft_vm;

#define WEFT_VM_PAGE (4 * 1024)

static void weft_vm_new_page(weft_vm *v)
{
	zend_vm_stack page = emalloc(WEFT_VM_PAGE);
	page->top = ZEND_VM_STACK_ELEMENTS(page);
	page->end = (zval *) ((char *) page + WEFT_VM_PAGE);
	page->prev = NULL;
	page->top++;
	v->vm_stack = page;
	v->vm_stack_top = page->top;
	v->vm_stack_end = page->end;
	v->vm_stack_page_size = WEFT_VM_PAGE;

	/* A bottom frame, so calls made from native code and uncaught exceptions behave as they
	 * do under a running script instead of being fatal on the spot. */
	zend_execute_data *base = (zend_execute_data *) page->top;
	memset(base, 0, sizeof(zend_execute_data));
	base->func = (zend_function *) &zend_pass_function;
	v->vm_stack_top = page->top + ZEND_CALL_FRAME_SLOT;
	v->current_execute_data = base;
}

void *weft_vm_new(void)
{
	weft_vm *v = calloc(1, sizeof(*v));
	weft_vm_new_page(v);
	v->error_handling = EH_NORMAL;
	return v;
}

/* A state that will be filled by the first save (used for the thread's main context). */
void *weft_vm_blank(void)
{
	return calloc(1, sizeof(weft_vm));
}

void weft_vm_save(void *p)
{
	weft_vm *v = p;
	v->vm_stack = EG(vm_stack);
	v->vm_stack_top = EG(vm_stack_top);
	v->vm_stack_end = EG(vm_stack_end);
	v->vm_stack_page_size = EG(vm_stack_page_size);
	v->current_execute_data = EG(current_execute_data);
	v->exception = EG(exception);
	v->prev_exception = EG(prev_exception);
	v->opline_before_exception = EG(opline_before_exception);
	v->error_handling = EG(error_handling);
	v->exception_class = EG(exception_class);
	v->jit_trace_num = EG(jit_trace_num);
	v->stack_base = EG(stack_base);
	v->stack_limit = EG(stack_limit);
}

void weft_vm_restore(void *p)
{
	weft_vm *v = p;
	EG(vm_stack) = v->vm_stack;
	EG(vm_stack_top) = v->vm_stack_top;
	EG(vm_stack_end) = v->vm_stack_end;
	EG(vm_stack_page_size) = v->vm_stack_page_size;
	EG(current_execute_data) = v->current_execute_data;
	EG(exception) = v->exception;
	EG(prev_exception) = v->prev_exception;
	EG(opline_before_exception) = v->opline_before_exception;
	EG(error_handling) = v->error_handling;
	EG(exception_class) = v->exception_class;
	EG(jit_trace_num) = v->jit_trace_num;
	EG(stack_base) = v->stack_base;
	EG(stack_limit) = v->stack_limit;
}

void weft_vm_free(void *p)
{
	free(p);
}

/* Releases the executor stack of the coroutine that is currently loaded. */
void weft_vm_stack_destroy(void)
{
	zend_vm_stack page = EG(vm_stack);
	while (page != NULL) {
		zend_vm_stack prev = page->prev;
		efree(page);
		page = prev;
	}
	EG(vm_stack) = NULL;
	EG(vm_stack_top) = NULL;
	EG(vm_stack_end) = NULL;
}

/* Bounds of the C stack the loaded coroutine runs on, for PHP's recursion guard. */
void weft_vm_set_stack(void *base, void *limit)
{
	EG(stack_base) = base;
	EG(stack_limit) = limit;
}

/* ---------------------------------------------------------------- module glue */

static PHP_MINIT_FUNCTION(weft)
{
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "Weft\\Exception", NULL);
	weft_ce_exception = zend_register_internal_class_ex(&ce, zend_ce_exception);

	memcpy(&weft_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	weft_handlers.offset = XtOffsetOf(weft_obj, std);
	weft_handlers.free_obj = weft_free;
	weft_handlers.clone_obj = NULL;

	return weft_rs_minit() == 0 ? SUCCESS : FAILURE;
}

static PHP_RSHUTDOWN_FUNCTION(weft)
{
	weft_rs_rshutdown();
	if (weft_stashed_exception != NULL) {
		OBJ_RELEASE(weft_stashed_exception);
		weft_stashed_exception = NULL;
	}
	return SUCCESS;
}

static PHP_MINFO_FUNCTION(weft)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "weft support", "enabled");
	php_info_print_table_row(2, "version", "0.1.0");
	php_info_print_table_end();
}

zend_module_entry weft_module_entry = {
	STANDARD_MODULE_HEADER,
	"weft",
	NULL,
	PHP_MINIT(weft),
	NULL,
	NULL,
	PHP_RSHUTDOWN(weft),
	PHP_MINFO(weft),
	"0.1.0",
	STANDARD_MODULE_PROPERTIES
};

/* Exported from Rust so the linker keeps this object. */
void *weft_module(void)
{
	return &weft_module_entry;
}
