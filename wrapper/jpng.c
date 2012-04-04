#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include "codejail.h"
#include "png.h"

static png_structp saved_ptr;
static FILE *saved_fp, *saved_shadowfp;
static png_infop saved_info;
static png_uint_32 saved_width, saved_height, saved_rowbytes;

static inline void new_saved_data (png_structp png_ptr)
{
	if (saved_ptr != png_ptr) {
		saved_ptr = png_ptr;
		saved_fp = saved_shadowfp = NULL;
		saved_info = NULL;
		saved_width = saved_height = saved_rowbytes = 0;
	}
}

static void *callback_wapper2 (void *(*func)(void *, void *), void *arg1, void *arg2)
{
	void *retval = func(arg1, arg2);
	fprintf(stderr, "callback %p(%p, %p) = %p\n", func, arg1, arg2, retval);
	return retval;
}

static void *callback_wapper4 (void *(*func)(void *, void *, void *, void *),
		void *arg1, void *arg2, void *arg3, void *arg4)
{
	void *retval = func(arg1, arg2, arg3, arg4);
	fprintf(stderr, "callback %p(%p, %p, %p, %p) = %p\n", func, arg1, arg2, arg3, arg4, retval);
	return retval;
}

png_infop png_create_info_struct (png_structp png_ptr)
{
	static png_infop (*real_png)(png_structp) = NULL;
	if(!real_png) 
		real_png = (png_infop (*) (png_structp))dlsym(RTLD_NEXT,"png_create_info_struct");
	if (cj_get_state() != CJS_MAIN)
		return real_png(png_ptr);

	fprintf(stderr, "In png_create_info_struct function\n");
	png_infop ret = (png_infop)cj_jail(real_png, 1, png_ptr);
	new_saved_data(png_ptr);
	saved_info = ret;
	return ret;
}

png_structp png_create_read_struct (png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn)
{
	static png_structp (*real_png)(png_const_charp, png_voidp, png_error_ptr, png_error_ptr) = NULL;
	if(!real_png)
		real_png = (png_structp (*) (png_const_charp, png_voidp, png_error_ptr, png_error_ptr))dlsym(RTLD_NEXT,"png_create_read_struct");
	if (cj_get_state() != CJS_MAIN)
		return real_png(user_png_ver, error_ptr, error_fn, warn_fn);

	// void usr_error_func(png_structp png_ptr, png_const_charp message);
	// void usr_png_malloc(png_structp png, png_size_t size)
	fprintf(stderr, "In png_create_read_struct\n");
	png_structp ret = (png_structp)cj_jail(real_png, 4, user_png_ver, error_ptr,
			cj_reg_callback(error_fn, callback_wapper2, 2),
			cj_reg_callback(warn_fn, callback_wapper2, 2));
	return ret;
}

png_structp png_create_read_struct_2 (png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn, png_voidp mem_ptr, png_malloc_ptr malloc_fn, png_free_ptr free_fn)
{
	static png_structp (*realfunc) (png_const_charp, png_voidp, png_error_ptr, png_error_ptr, png_voidp, png_malloc_ptr, png_free_ptr) = NULL;
	if (!realfunc)
		realfunc = (png_structp (*)(png_const_charp, png_voidp, png_error_ptr, png_error_ptr, png_voidp, png_malloc_ptr, png_free_ptr))dlsym(RTLD_NEXT, "png_create_read_struct_2");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(user_png_ver, error_ptr, error_fn, warn_fn, mem_ptr, malloc_fn, free_fn);
	}

	fprintf(stderr, "Jailing png_create_read_struct_2(%p, %p, %p, %p, %p, %p, %p)\n", user_png_ver, error_ptr, error_fn, warn_fn, mem_ptr, malloc_fn, free_fn);
	png_structp retval = (png_structp)cj_jail(realfunc, 7, user_png_ver, error_ptr,
			cj_reg_callback(error_fn, callback_wapper2, 2),
			cj_reg_callback(warn_fn, callback_wapper2, 2),
			mem_ptr, NULL, NULL);

	return retval;
}

png_structp png_create_write_struct (png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn)
{
	static png_structp (*realfunc) (png_const_charp, png_voidp, png_error_ptr, png_error_ptr) = NULL;
	if (!realfunc)
		realfunc = (png_structp (*)(png_const_charp, png_voidp, png_error_ptr, png_error_ptr))dlsym(RTLD_NEXT, "png_create_write_struct");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(user_png_ver, error_ptr, error_fn, warn_fn);
	}

	fprintf(stderr, "Jailing png_create_write_struct(%p, %p, %p, %p)\n", user_png_ver, error_ptr, error_fn, warn_fn);
	png_structp retval = (png_structp)cj_jail(realfunc, 4, user_png_ver, error_ptr,
			cj_reg_callback(error_fn, callback_wapper2, 2),
			cj_reg_callback(warn_fn, callback_wapper2, 2));

	return retval;
}

png_structp png_create_write_struct_2 (png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn, png_voidp mem_ptr, png_malloc_ptr malloc_fn, png_free_ptr free_fn)
{
	static png_structp (*realfunc) (png_const_charp, png_voidp, png_error_ptr, png_error_ptr, png_voidp, png_malloc_ptr, png_free_ptr) = NULL;
	if (!realfunc)
		realfunc = (png_structp (*)(png_const_charp, png_voidp, png_error_ptr, png_error_ptr, png_voidp, png_malloc_ptr, png_free_ptr))dlsym(RTLD_NEXT, "png_create_write_struct_2");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(user_png_ver, error_ptr, error_fn, warn_fn, mem_ptr, malloc_fn, free_fn);
	}

	fprintf(stderr, "Jailing png_create_write_struct_2(%p, %p, %p, %p, %p, %p, %p)\n", user_png_ver, error_ptr, error_fn, warn_fn, mem_ptr, malloc_fn, free_fn);
	png_structp retval = (png_structp)cj_jail(realfunc, 7, user_png_ver, error_ptr,
			cj_reg_callback(error_fn, callback_wapper2, 2),
			cj_reg_callback(warn_fn, callback_wapper2, 2),
			mem_ptr, NULL, NULL);

	return retval;
}

void png_destroy_read_struct (png_structpp png_ptr_ptr, png_infopp info_ptr_ptr, png_infopp end_info_ptr_ptr)
{
	static void (*real_png)(png_structpp, png_infopp, png_infopp) = NULL;
	if(!real_png)
		real_png = (void (*) (png_structpp, png_infopp, png_infopp))dlsym(RTLD_NEXT,"png_destroy_read_struct");
	if (cj_get_state() != CJS_MAIN) {
		real_png(png_ptr_ptr, info_ptr_ptr, end_info_ptr_ptr);
		return;
	}

	fprintf(stderr, "In png_destroy_read_struct\n");
	if (*png_ptr_ptr == saved_ptr)
		new_saved_data(NULL);

	cj_jail(real_png, 3, png_ptr_ptr, info_ptr_ptr, end_info_ptr_ptr);
	cj_recv(png_ptr_ptr, sizeof(png_structp));
	cj_recv(info_ptr_ptr, sizeof(png_infop));
	cj_recv(end_info_ptr_ptr, sizeof(png_infop));
}

void png_destroy_write_struct (png_structpp png_ptr_ptr, png_infopp info_ptr_ptr)
{
	static void (*realfunc) (png_structpp, png_infopp) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structpp, png_infopp))dlsym(RTLD_NEXT, "png_destroy_write_struct");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr_ptr, info_ptr_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_destroy_write_struct(%p, %p)\n", png_ptr_ptr, info_ptr_ptr);
	cj_jail(realfunc, 2, png_ptr_ptr, info_ptr_ptr);
	cj_recv(png_ptr_ptr, sizeof(png_structp));
	cj_recv(info_ptr_ptr, sizeof(png_infop));
}

void png_error (png_structp png_ptr, png_const_charp error_message)
{
	static void (*realfunc) (png_structp, png_const_charp) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_const_charp))dlsym(RTLD_NEXT, "png_error");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, error_message);
		return;
	}

	fprintf(stderr, "Jailing png_error(%p, %p)\n", png_ptr, error_message);
	cj_jail(realfunc, 2, png_ptr, error_message);
}

png_byte png_get_bit_depth (png_structp png_ptr, png_infop info_ptr)
{
	static png_byte (*realfunc) (png_structp, png_infop) = NULL;
	if (!realfunc)
		realfunc = (png_byte (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_get_bit_depth");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr, info_ptr);
	}

	fprintf(stderr, "Jailing png_get_bit_depth(%p, %p)\n", png_ptr, info_ptr);
	png_byte retval = (png_byte)cj_jail(realfunc, 2, png_ptr, info_ptr);

	return retval;
}

png_byte png_get_channels (png_structp png_ptr, png_infop info_ptr)
{
	static png_byte (*realfunc) (png_structp, png_infop) = NULL;
	if (!realfunc)
		realfunc = (png_byte (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_get_channels");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr, info_ptr);
	}

	fprintf(stderr, "Jailing png_get_channels(%p, %p)\n", png_ptr, info_ptr);
	png_byte retval = (png_byte)cj_jail(realfunc, 2, png_ptr, info_ptr);

	return retval;
}

png_voidp png_get_error_ptr (png_structp png_ptr)
{
	static png_voidp (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (png_voidp (*)(png_structp))dlsym(RTLD_NEXT, "png_get_error_ptr");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr);
	}

	fprintf(stderr, "Jailing png_get_error_ptr(%p)\n", png_ptr);
	png_voidp retval = (png_voidp)cj_jail(realfunc, 1, png_ptr);

	return retval;
}

png_uint_32 png_get_iCCP (png_structp png_ptr, png_infop info_ptr, png_charpp name, int *compression_type, png_charpp profile, png_uint_32 *proflen)
{
	static png_uint_32 (*realfunc) (png_structp, png_infop, png_charpp, int *, png_charpp, png_uint_32 *) = NULL;
	if (!realfunc)
		realfunc = (png_uint_32 (*)(png_structp, png_infop, png_charpp, int *, png_charpp, png_uint_32 *))dlsym(RTLD_NEXT, "png_get_iCCP");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr, info_ptr, name, compression_type, profile, proflen);
	}

	fprintf(stderr, "Jailing png_get_iCCP(%p, %p, %p, %p, %p, %p)\n", png_ptr, info_ptr, name, compression_type, profile, proflen);
	png_uint_32 retval = (png_uint_32)cj_jail(realfunc, 6, png_ptr, info_ptr, name, compression_type, profile, proflen);
	cj_recv(name, sizeof(png_charp));
	cj_recv(compression_type, sizeof(int));
	cj_recv(profile, sizeof(png_charp));
	cj_recv(proflen, sizeof(png_uint_32));

	return retval;
}

png_uint_32 png_get_IHDR (png_structp png_ptr, png_infop info_ptr, png_uint_32 *width, png_uint_32 *height, int *bit_depth, int *color_type, int *interlace_method, int *compression_method, int *filter_method)
{
	static png_uint_32 (*realfunc) (png_structp, png_infop, png_uint_32 *, png_uint_32 *, int *, int *, int *, int *, int *) = NULL;
	if (!realfunc)
		realfunc = (png_uint_32 (*)(png_structp, png_infop, png_uint_32 *, png_uint_32 *, int *, int *, int *, int *, int *))dlsym(RTLD_NEXT, "png_get_IHDR");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr, info_ptr, width, height, bit_depth, color_type, interlace_method, compression_method, filter_method);
	}

	fprintf(stderr, "Jailing png_get_IHDR(%p, %p, %p, %p, %p, %p, %p, %p, %p)\n", png_ptr, info_ptr, width, height, bit_depth, color_type, interlace_method, compression_method, filter_method);
	png_uint_32 retval = (png_uint_32)cj_jail(realfunc, 9, png_ptr, info_ptr, width, height, bit_depth, color_type, interlace_method, compression_method, filter_method);
	cj_recv(width, sizeof(png_uint_32));
	cj_recv(height, sizeof(png_uint_32));
	cj_recv(bit_depth, sizeof(int));
	cj_recv(color_type, sizeof(int));
	cj_recv(interlace_method, sizeof(int));
	cj_recv(compression_method, sizeof(int));
	cj_recv(filter_method, sizeof(int));

	return retval;
}

png_uint_32 png_get_image_height (png_structp png_ptr, png_infop info_ptr)
{
	static png_uint_32 (*real_png) (png_structp, png_infop) = NULL;
	if (!real_png)
		real_png = (png_uint_32 (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_get_image_height");
	if (cj_get_state() != CJS_MAIN)
		return real_png(png_ptr, info_ptr);

	fprintf(stderr, "In png_get_image_height\n");
	return cj_jail(real_png, 2, png_ptr, info_ptr);
}

png_uint_32 png_get_rowbytes (png_structp png_ptr, png_infop info_ptr)
{
	static png_uint_32 (*real_png) (png_structp, png_infop) = NULL;
	if (!real_png)
		real_png = (png_uint_32 (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_get_rowbytes");
	if (cj_get_state() != CJS_MAIN)
		return real_png(png_ptr, info_ptr);

	fprintf(stderr, "In png_get_rowbytes\n");
	return cj_jail(real_png, 2, png_ptr, info_ptr);
}

png_voidp png_get_io_ptr (png_structp png_ptr)
{
	static png_voidp (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (png_voidp (*)(png_structp))dlsym(RTLD_NEXT, "png_get_io_ptr");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr);
	}

	fprintf(stderr, "Jailing png_get_io_ptr(%p)\n", png_ptr);
	png_voidp retval = (png_voidp)cj_jail(realfunc, 1, png_ptr);

	return retval;
}

png_voidp png_get_progressive_ptr (png_structp png_ptr)
{
	static png_voidp (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (png_voidp (*)(png_structp))dlsym(RTLD_NEXT, "png_get_progressive_ptr");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr);
	}

	fprintf(stderr, "Jailing png_get_progressive_ptr(%p)\n", png_ptr);
	png_voidp retval = (png_voidp)cj_jail(realfunc, 1, png_ptr);

	return retval;
}

png_uint_32 png_get_text (png_structp png_ptr, png_infop info_ptr, png_textp *text_ptr, int *num_text)
{
	static png_uint_32 (*realfunc) (png_structp, png_infop, png_textp *, int *) = NULL;
	if (!realfunc)
		realfunc = (png_uint_32 (*)(png_structp, png_infop, png_textp *, int *))dlsym(RTLD_NEXT, "png_get_text");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr, info_ptr, text_ptr, num_text);
	}

	fprintf(stderr, "Jailing png_get_text(%p, %p, %p, %p)\n", png_ptr, info_ptr, text_ptr, num_text);
	png_uint_32 retval = (png_uint_32)cj_jail(realfunc, 4, png_ptr, info_ptr, text_ptr, num_text);
	cj_recv(text_ptr, sizeof(png_textp));
	cj_recv(num_text, sizeof(int));

	return retval;
}

png_uint_32 png_get_valid (png_structp png_ptr, png_infop info_ptr, png_uint_32 flag)
{
	static png_uint_32 (*realfunc) (png_structp, png_infop, png_uint_32) = NULL;
	if (!realfunc)
		realfunc = (png_uint_32 (*)(png_structp, png_infop, png_uint_32))dlsym(RTLD_NEXT, "png_get_valid");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr, info_ptr, flag);
	}

	fprintf(stderr, "Jailing png_get_valid(%p, %p, %lu)\n", png_ptr, info_ptr, flag);
	png_uint_32 retval = (png_uint_32)cj_jail(realfunc, 3, png_ptr, info_ptr, flag);

	return retval;
}

void png_init_io(png_structp png_ptr, png_FILE_p fp)
{
	static void (*real_png)(png_structp, png_FILE_p) = NULL;
	if(!real_png)
		real_png = (void (*) (png_structp, png_FILE_p))dlsym(RTLD_NEXT,"png_init_io");
	if (cj_get_state() != CJS_MAIN) {
		real_png(png_ptr, fp);
		return;
	}

	fprintf(stderr, "In png_init_io function\n");

	new_saved_data(png_ptr);
	saved_fp = fp;
	saved_shadowfp = cj_duplicate_file(fp);
	cj_jail(real_png, 2, png_ptr, saved_shadowfp);
}

void png_process_data (png_structp png_ptr, png_infop info_ptr, png_bytep buffer, png_size_t buffer_size)
{
	static void (*realfunc) (png_structp, png_infop, png_bytep, png_size_t) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop, png_bytep, png_size_t))dlsym(RTLD_NEXT, "png_process_data");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr, buffer, buffer_size);
		return;
	}

	fprintf(stderr, "Jailing png_process_data(%p, %p, %p, %zd)\n", png_ptr, info_ptr, buffer, buffer_size);
	cj_jail(realfunc, 4, png_ptr, info_ptr, buffer, buffer_size);
}

void png_progressive_combine_row (png_structp png_ptr, png_bytep old_row, png_bytep new_row)
{
	static void (*realfunc) (png_structp, png_bytep, png_bytep) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_bytep, png_bytep))dlsym(RTLD_NEXT, "png_progressive_combine_row");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, old_row, new_row);
		return;
	}

	assert(saved_ptr == png_ptr);
	if (saved_rowbytes == 0) {
		assert(saved_info != NULL);
		saved_rowbytes = png_get_rowbytes(png_ptr, saved_info);
	}

	fprintf(stderr, "Jailing png_progressive_combine_row(%p, %p, %p)\n", png_ptr, old_row, new_row);
	cj_jail(realfunc, 3, png_ptr, old_row, new_row);
	cj_recv(old_row, saved_rowbytes);
}

void png_read_end (png_structp png_ptr, png_infop info_ptr)
{
	static void (*real_png)(png_structp, png_infop) = NULL;
	if(!real_png)
		real_png = (void (*) (png_structp, png_infop))dlsym(RTLD_NEXT,"png_read_end");
	if (cj_get_state() != CJS_MAIN) {
		real_png(png_ptr, info_ptr);
		return;
	}

	fprintf(stderr,"In png_read_end\n");
	cj_jail(real_png, 2, png_ptr, info_ptr);
}

void png_read_image (png_structp png_ptr, png_bytepp image)
{
	static void (*real_png)(png_structp, png_bytepp) = NULL;
	if(!real_png)
		real_png = (void (*) (png_structp, png_bytepp))dlsym(RTLD_NEXT,"png_read_image");
	if (cj_get_state() != CJS_MAIN) {
		real_png(png_ptr, image);
		return;
	}

	fprintf(stderr,"In png_read_image\n");
	assert(saved_ptr == png_ptr && saved_info != NULL);
	png_uint_32 height = png_get_image_height(png_ptr, saved_info);
	png_uint_32 rowbytes = png_get_rowbytes(png_ptr, saved_info);
	fprintf(stderr, "height=%lu, rowbytes=%lu\n", height, rowbytes);
	assert(height > 0 && rowbytes > 0);
	cj_jail(real_png, 2, png_ptr, image);
	cj_recv(image, height * sizeof(png_bytep));
	fprintf(stderr, "image[0]=%p, image[1]=%p\n", image[0], image[1]);
	int i;
	for (i = 0; i < height; i ++)
		cj_recv(image[i], rowbytes);
	fprintf(stderr, "image[%lu][%lu]=%x\n", height/2, rowbytes/2, image[height/2][rowbytes/2]);
}

void png_read_info (png_structp png_ptr, png_infop info_ptr)
{
	static void (*real_png)(png_structp, png_infop) = NULL;
	if(!real_png)
		real_png = (void (*) (png_structp, png_infop))dlsym(RTLD_NEXT,"png_read_info");
	if (cj_get_state() != CJS_MAIN) {
		real_png(png_ptr, info_ptr);
		return;
	}

	fprintf(stderr,"In png_read_info\n");
	assert(cj_memtype(info_ptr) == CJMT_SHARED); // make sure info is created using png_create_info_struct
	cj_jail(real_png, 2, png_ptr, info_ptr);
}

void png_read_update_info (png_structp png_ptr, png_infop info_ptr)
{
	static void (*realfunc) (png_structp, png_infop) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_read_update_info");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_read_update_info(%p, %p)\n", png_ptr, info_ptr);
	cj_jail(realfunc, 2, png_ptr, info_ptr);
}

void png_set_compression_level (png_structp png_ptr, int level)
{
	static void (*realfunc) (png_structp, int) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, int))dlsym(RTLD_NEXT, "png_set_compression_level");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, level);
		return;
	}

	fprintf(stderr, "Jailing png_set_compression_level(%p, %d)\n", png_ptr, level);
	cj_jail(realfunc, 2, png_ptr, level);
}

void png_set_expand (png_structp png_ptr)
{
	static void (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp))dlsym(RTLD_NEXT, "png_set_expand");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_set_expand(%p)\n", png_ptr);
	cj_jail(realfunc, 1, png_ptr);
}

void png_set_gray_to_rgb (png_structp png_ptr)
{
	static void (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp))dlsym(RTLD_NEXT, "png_set_gray_to_rgb");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_set_gray_to_rgb(%p)\n", png_ptr);
	cj_jail(realfunc, 1, png_ptr);
}

void png_set_iCCP (png_structp png_ptr, png_infop info_ptr, png_charp name, int compression_type, png_charp profile, png_uint_32 proflen)
{
	static void (*realfunc) (png_structp, png_infop, png_charp, int, png_charp, png_uint_32) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop, png_charp, int, png_charp, png_uint_32))dlsym(RTLD_NEXT, "png_set_iCCP");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr, name, compression_type, profile, proflen);
		return;
	}

	fprintf(stderr, "Jailing png_set_iCCP(%p, %p, %p, %d, %p, %lu)\n", png_ptr, info_ptr, name, compression_type, profile, proflen);
	cj_jail(realfunc, 6, png_ptr, info_ptr, name, compression_type, profile, proflen);
}

void png_set_IHDR (png_structp png_ptr, png_infop info_ptr, png_uint_32 width, png_uint_32 height, int bit_depth, int color_type, int interlace_method, int compression_method, int filter_method)
{
	static void (*realfunc) (png_structp, png_infop, png_uint_32, png_uint_32, int, int, int, int, int) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop, png_uint_32, png_uint_32, int, int, int, int, int))dlsym(RTLD_NEXT, "png_set_IHDR");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr, width, height, bit_depth, color_type, interlace_method, compression_method, filter_method);
		return;
	}

	fprintf(stderr, "Jailing png_set_IHDR(%p, %p, %lu, %lu, %d, %d, %d, %d, %d)\n", png_ptr, info_ptr, width, height, bit_depth, color_type, interlace_method, compression_method, filter_method);
	assert(cj_memtype(info_ptr) == CJMT_SHARED); // make sure info is created using png_create_info_struct
	cj_jail(realfunc, 9, png_ptr, info_ptr, width, height, bit_depth, color_type, interlace_method, compression_method, filter_method);
}

int png_set_interlace_handling (png_structp png_ptr)
{
	static int (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (int (*)(png_structp))dlsym(RTLD_NEXT, "png_set_interlace_handling");
	if (cj_get_state() != CJS_MAIN) {
		return realfunc(png_ptr);
	}

	fprintf(stderr, "Jailing png_set_interlace_handling(%p)\n", png_ptr);
	int retval = (int)cj_jail(realfunc, 1, png_ptr);

	return retval;
}

void png_set_packing (png_structp png_ptr)
{
	static void (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp))dlsym(RTLD_NEXT, "png_set_packing");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_set_packing(%p)\n", png_ptr);
	cj_jail(realfunc, 1, png_ptr);
}

void png_set_progressive_read_fn (png_structp png_ptr, png_voidp progressive_ptr, png_progressive_info_ptr info_fn, png_progressive_row_ptr row_fn, png_progressive_end_ptr end_fn)
{
	static void (*realfunc) (png_structp, png_voidp, png_progressive_info_ptr, png_progressive_row_ptr, png_progressive_end_ptr) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_voidp, png_progressive_info_ptr, png_progressive_row_ptr, png_progressive_end_ptr))dlsym(RTLD_NEXT, "png_set_progressive_read_fn");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, progressive_ptr, info_fn, row_fn, end_fn);
		return;
	}

	// void usr_info_callback(png_structp png_ptr, png_infop info_ptr);
	// void usr_row_callback(png_structp png_ptr, png_bytep new_row, png_uint_32 row_num, int pass);
	// void usr_end_callback(png_structp png_ptr, png_infop info_ptr);
	fprintf(stderr, "Jailing png_set_progressive_read_fn(%p, %p, %p, %p, %p)\n", png_ptr, progressive_ptr, info_fn, row_fn, end_fn);
	cj_jail(realfunc, 5, png_ptr, progressive_ptr,
			cj_reg_callback(info_fn, NULL, 2),
			cj_reg_callback(row_fn, callback_wapper4, 4),
			cj_reg_callback(end_fn, callback_wapper2, 2));
}

void png_set_sBIT (png_structp png_ptr, png_infop info_ptr, png_color_8p sig_bit)
{
	static void (*realfunc) (png_structp, png_infop, png_color_8p) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop, png_color_8p))dlsym(RTLD_NEXT, "png_set_sBIT");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr, sig_bit);
		return;
	}

	fprintf(stderr, "Jailing png_set_sBIT(%p, %p, %p)\n", png_ptr, info_ptr, sig_bit);
	cj_jail(realfunc, 3, png_ptr, info_ptr, sig_bit);
}

void png_set_shift (png_structp png_ptr, png_color_8p true_bits)
{
	static void (*realfunc) (png_structp, png_color_8p) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_color_8p))dlsym(RTLD_NEXT, "png_set_shift");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, true_bits);
		return;
	}

	fprintf(stderr, "Jailing png_set_shift(%p, %p)\n", png_ptr, true_bits);
	cj_jail(realfunc, 2, png_ptr, true_bits);
}

void png_set_sig_bytes (png_structp png_ptr, int num_bytes)
{
	static void (*real_png)(png_structp, int) = NULL;
	if (!real_png)
		real_png = (void (*)(png_structp, int))dlsym(RTLD_NEXT, "png_set_sig_bytes");
	if (cj_get_state() != CJS_MAIN) {
		real_png(png_ptr, num_bytes);
		return;
	}

	fprintf(stderr,"In png_set_sig_bytes\n");
	if (num_bytes > 0) {
		assert(png_ptr == saved_ptr && saved_shadowfp != NULL);
		cj_jail(rewind, 1, saved_shadowfp);
		assert(cj_jail(fseek, 3, saved_shadowfp, num_bytes, SEEK_SET) == 0);
	}

	cj_jail(real_png, 2, png_ptr, num_bytes);
}

void png_set_strip_16 (png_structp png_ptr)
{
	static void (*realfunc) (png_structp) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp))dlsym(RTLD_NEXT, "png_set_strip_16");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_set_strip_16(%p)\n", png_ptr);
	cj_jail(realfunc, 1, png_ptr);
}

void png_set_text (png_structp png_ptr, png_infop info_ptr, png_textp text_ptr, int num_text)
{
	static void (*realfunc) (png_structp, png_infop, png_textp, int) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop, png_textp, int))dlsym(RTLD_NEXT, "png_set_text");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr, text_ptr, num_text);
		return;
	}

	fprintf(stderr, "Jailing png_set_text(%p, %p, %p, %d)\n", png_ptr, info_ptr, text_ptr, num_text);
	cj_jail(realfunc, 4, png_ptr, info_ptr, text_ptr, num_text);
}

int png_sig_cmp (png_bytep sig, png_size_t start, png_size_t num_to_check)
{
	static int (*real_png)(png_bytep, png_size_t, png_size_t) = NULL;
	if(!real_png)
		real_png = (int (*) (png_bytep, png_size_t, png_size_t))dlsym(RTLD_NEXT,"png_sig_cmp");
	if (cj_get_state() != CJS_MAIN)
		return real_png(sig, start, num_to_check);

	fprintf(stderr, "In png_sig_cmp\n");
	int ret = cj_jail(real_png, 3, sig, start, num_to_check);
	return ret;
}

void png_set_write_fn (png_structp png_ptr, png_voidp io_ptr, png_rw_ptr write_data_fn, png_flush_ptr output_flush_fn)
{
	static void (*realfunc) (png_structp, png_voidp, png_rw_ptr, png_flush_ptr) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_voidp, png_rw_ptr, png_flush_ptr))dlsym(RTLD_NEXT, "png_set_write_fn");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, io_ptr, write_data_fn, output_flush_fn);
		return;
	}

	fprintf(stderr, "Jailing png_set_write_fn(%p, %p, %p, %p)\n", png_ptr, io_ptr, write_data_fn, output_flush_fn);
	cj_jail(realfunc, 4, png_ptr, io_ptr,
			cj_reg_callback(write_data_fn, callback_wapper2, 0),
			cj_reg_callback(output_flush_fn, callback_wapper2, 0));
}

void png_write_end (png_structp png_ptr, png_infop info_ptr)
{
	static void (*realfunc) (png_structp, png_infop) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_write_end");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_write_end(%p, %p)\n", png_ptr, info_ptr);
	cj_jail(realfunc, 2, png_ptr, info_ptr);
}

void png_write_info (png_structp png_ptr, png_infop info_ptr)
{
	static void (*realfunc) (png_structp, png_infop) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_infop))dlsym(RTLD_NEXT, "png_write_info");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, info_ptr);
		return;
	}

	fprintf(stderr, "Jailing png_write_info(%p, %p)\n", png_ptr, info_ptr);
	assert(cj_memtype(info_ptr) == CJMT_SHARED); // make sure info is created using png_create_info_struct
	cj_jail(realfunc, 2, png_ptr, info_ptr);
}

void png_write_rows (png_structp png_ptr, png_bytepp row, png_uint_32 num_rows)
{
	static void (*realfunc) (png_structp, png_bytepp, png_uint_32) = NULL;
	if (!realfunc)
		realfunc = (void (*)(png_structp, png_bytepp, png_uint_32))dlsym(RTLD_NEXT, "png_write_rows");
	if (cj_get_state() != CJS_MAIN) {
		realfunc(png_ptr, row, num_rows);
		return;
	}

	fprintf(stderr, "Jailing png_write_rows(%p, %p, %lu)\n", png_ptr, row, num_rows);
	cj_jail(realfunc, 3, png_ptr, row, num_rows);
}
