/*
Copyright 2006 - 2022 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <WinBase.h>
#endif

#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Debugger.h"
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibCrypto.h"
#include "../microstack/ILibRemoteLogging.h"

#ifdef _POSIX
	#ifdef __APPLE__
		#include <util.h>
	#else
		#include <termios.h>
	#endif
#endif


#define ILibDuktape_Timer_Ptrs					"\xFF_DuktapeTimer_PTRS"
#define ILibDuktape_Queue_Ptr					"\xFF_Queue"
#define ILibDuktape_Stream_Buffer				"\xFF_BUFFER"
#define ILibDuktape_Stream_ReadablePtr			"\xFF_ReadablePtr"
#define ILibDuktape_Stream_WritablePtr			"\xFF_WritablePtr"
#define ILibDuktape_Console_Destination			"\xFF_Console_Destination"
#define ILibDuktape_Console_LOG_Destination		"\xFF_Console_Destination"
#define ILibDuktape_Console_WARN_Destination	"\xFF_Console_WARN_Destination"
#define ILibDuktape_Console_ERROR_Destination	"\xFF_Console_ERROR_Destination"
#define ILibDuktape_Console_INFO_Level			"\xFF_Console_INFO_Level"
#define ILibDuktape_Console_SessionID			"\xFF_Console_SessionID"

#define ILibDuktape_DescriptorEvents_ChainLink	"\xFF_DescriptorEvents_ChainLink"
#define ILibDuktape_DescriptorEvents_Table		"\xFF_DescriptorEvents_Table"
#define ILibDuktape_DescriptorEvents_HTable		"\xFF_DescriptorEvents_HTable"
#define ILibDuktape_DescriptorEvents_CURRENT	"\xFF_DescriptorEvents_CURRENT"
#define ILibDuktape_DescriptorEvents_FD			"\xFF_DescriptorEvents_FD"
#define ILibDuktape_DescriptorEvents_Options	"\xFF_DescriptorEvents_Options"
#define ILibDuktape_DescriptorEvents_WaitHandle "\xFF_DescriptorEvents_WindowsWaitHandle"
#define ILibDuktape_ChainViewer_PromiseList		"\xFF_ChainViewer_PromiseList"
#define CP_ISO8859_1							28591

#define ILibDuktape_AltRequireTable				"\xFF_AltRequireTable"
#define ILibDuktape_AddCompressedModule(ctx, name, b64str) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_pcall_method(ctx, 2);duk_pop(ctx);
#define ILibDuktape_AddCompressedModuleEx(ctx, name, b64str, stamp) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_push_string(ctx,stamp);duk_pcall_method(ctx, 3);duk_pop(ctx);

extern void* _duk_get_first_object(void *ctx);
extern void* _duk_get_next_object(void *ctx, void *heapptr);
extern duk_ret_t ModSearchTable_Get(duk_context *ctx, duk_idx_t table, char *key, char *id);


typedef enum ILibDuktape_Console_DestinationFlags
{
	ILibDuktape_Console_DestinationFlags_DISABLED		= 0,
	ILibDuktape_Console_DestinationFlags_StdOut			= 1,
	ILibDuktape_Console_DestinationFlags_ServerConsole	= 2,
	ILibDuktape_Console_DestinationFlags_WebLog			= 4,
	ILibDuktape_Console_DestinationFlags_LogFile		= 8
}ILibDuktape_Console_DestinationFlags;

#ifdef WIN32
typedef struct ILibDuktape_DescriptorEvents_WindowsWaitHandle
{
	HANDLE waitHandle;
	HANDLE eventThread;
	void *chain;
	duk_context *ctx;
	void *object;
}ILibDuktape_DescriptorEvents_WindowsWaitHandle;
#endif

int g_displayStreamPipeMessages = 0;
int g_displayFinalizerMessages = 0;
extern int GenerateSHA384FileHash(char *filePath, char *fileHash);

duk_ret_t ILibDuktape_Pollyfills_Buffer_slice(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *buffer;
	char *out;
	duk_size_t bufferLen;
	int offset = 0;
	duk_push_this(ctx);

	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	if (nargs >= 1)
	{
		offset = duk_require_int(ctx, 0);
		bufferLen -= offset;
	}
	if (nargs == 2)
	{
		bufferLen = (duk_size_t)duk_require_int(ctx, 1) - offset;
	}
	duk_push_fixed_buffer(ctx, bufferLen);
	out = Duktape_GetBuffer(ctx, -1, NULL);
	memcpy_s(out, bufferLen, buffer + offset, bufferLen);
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_randomFill(duk_context *ctx)
{
	int start, length;
	char *buffer;
	duk_size_t bufferLen;

	start = (int)(duk_get_top(ctx) == 0 ? 0 : duk_require_int(ctx, 0));
	length = (int)(duk_get_top(ctx) == 2 ? duk_require_int(ctx, 1) : -1);

	duk_push_this(ctx);
	buffer = (char*)Duktape_GetBuffer(ctx, -1, &bufferLen);
	if ((duk_size_t)length > bufferLen || length < 0)
	{
		length = (int)(bufferLen - start);
	}

	util_random(length, buffer + start);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Buffer_toString(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *buffer, *tmpBuffer;
	duk_size_t bufferLen = 0;
	char *cType;

	duk_push_this(ctx);									// [buffer]
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if (nargs == 0)
	{
		if (bufferLen == 0 || buffer == NULL)
		{
			duk_push_null(ctx);
		}
		else
		{
			// Just convert to a string
			duk_push_lstring(ctx, buffer, strnlen_s(buffer, bufferLen));			// [buffer][string]
		}
	}
	else
	{
		cType = (char*)duk_require_string(ctx, 0);
		if (strcmp(cType, "base64") == 0)
		{
			duk_push_fixed_buffer(ctx, ILibBase64EncodeLength(bufferLen));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			ILibBase64Encode((unsigned char*)buffer, (int)bufferLen, (unsigned char**)&tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else if (strcmp(cType, "hex") == 0)
		{
			duk_push_fixed_buffer(ctx, 1 + (bufferLen * 2));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			util_tohex(buffer, (int)bufferLen, tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else if (strcmp(cType, "hex:") == 0)
		{
			duk_push_fixed_buffer(ctx, 1 + (bufferLen * 3));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			util_tohex2(buffer, (int)bufferLen, tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
#ifdef WIN32
		else if (strcmp(cType, "utf16") == 0)
		{
			int sz = (MultiByteToWideChar(CP_UTF8, 0, buffer, (int)bufferLen, NULL, 0) * 2);
			WCHAR* b = duk_push_fixed_buffer(ctx, sz);
			duk_push_buffer_object(ctx, -1, 0, sz, DUK_BUFOBJ_NODEJS_BUFFER);
			MultiByteToWideChar(CP_UTF8, 0, buffer, (int)bufferLen, b, sz / 2);
		}
#endif
		else
		{
			return(ILibDuktape_Error(ctx, "Unrecognized parameter"));
		}
	}
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_from(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *str;
	duk_size_t strlength;
	char *encoding;
	char *buffer;
	size_t bufferLen;

	if (nargs == 1)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);
		buffer = duk_push_fixed_buffer(ctx, strlength);
		memcpy_s(buffer, strlength, str, strlength);
		duk_push_buffer_object(ctx, -1, 0, strlength, DUK_BUFOBJ_NODEJS_BUFFER);
		return(1);
	}
	else if(!(nargs == 2 && duk_is_string(ctx, 0) && duk_is_string(ctx, 1)))
	{
		return(ILibDuktape_Error(ctx, "usage not supported yet"));
	}

	str = (char*)duk_get_lstring(ctx, 0, &strlength);
	encoding = (char*)duk_require_string(ctx, 1);

	if (strcmp(encoding, "base64") == 0)
	{
		// Base64		
		buffer = duk_push_fixed_buffer(ctx, ILibBase64DecodeLength(strlength));
		bufferLen = ILibBase64Decode((unsigned char*)str, (int)strlength, (unsigned char**)&buffer);
		duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	}
	else if (strcmp(encoding, "hex") == 0)
	{		
		if (ILibString_StartsWith(str, (int)strlength, "0x", 2) != 0)
		{
			str += 2;
			strlength -= 2;
		}
		buffer = duk_push_fixed_buffer(ctx, strlength / 2);
		bufferLen = util_hexToBuf(str, (int)strlength, buffer);
		duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	}
	else if (strcmp(encoding, "utf8") == 0)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);
		buffer = duk_push_fixed_buffer(ctx, strlength);
		memcpy_s(buffer, strlength, str, strlength);
		duk_push_buffer_object(ctx, -1, 0, strlength, DUK_BUFOBJ_NODEJS_BUFFER);
		return(1);
	}
	else if (strcmp(encoding, "binary") == 0)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);

#ifdef WIN32
		int r = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, (int)strlength, NULL, 0);
		buffer = duk_push_fixed_buffer(ctx, 2 + (2 * r));
		strlength = (duk_size_t)MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, (int)strlength, (LPWSTR)buffer, r + 1);
		r = (int)WideCharToMultiByte(CP_ISO8859_1, 0, (LPCWCH)buffer, (int)strlength, NULL, 0, NULL, FALSE);
		duk_push_fixed_buffer(ctx, r);
		WideCharToMultiByte(CP_ISO8859_1, 0, (LPCWCH)buffer, (int)strlength, (LPSTR)Duktape_GetBuffer(ctx, -1, NULL), r, NULL, FALSE);
		duk_push_buffer_object(ctx, -1, 0, r, DUK_BUFOBJ_NODEJS_BUFFER);
#else
		duk_eval_string(ctx, "Buffer.fromBinary");	// [func]
		duk_dup(ctx, 0);
		duk_call(ctx, 1);
#endif
	}
	else
	{
		return(ILibDuktape_Error(ctx, "unsupported encoding"));
	}
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_readInt32BE(duk_context *ctx)
{
	int offset = duk_require_int(ctx, 0);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	duk_push_int(ctx, ntohl(((int*)(buffer + offset))[0]));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Buffer_alloc(duk_context *ctx)
{
	int sz = duk_require_int(ctx, 0);
	int fill = 0;

	if (duk_is_number(ctx, 1)) { fill = duk_require_int(ctx, 1); }

	duk_push_fixed_buffer(ctx, sz);
	char *buffer = Duktape_GetBuffer(ctx, -1, NULL);
	memset(buffer, fill, sz);
	duk_push_buffer_object(ctx, -1, 0, sz, DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}

void ILibDuktape_Polyfills_Buffer(duk_context *ctx)
{
	char extras[] =
		"Object.defineProperty(Buffer.prototype, \"swap32\",\
	{\
		value: function swap32()\
		{\
			var a = this.readUInt16BE(0);\
			var b = this.readUInt16BE(2);\
			this.writeUInt16LE(a, 2);\
			this.writeUInt16LE(b, 0);\
			return(this);\
		}\
	});";
	duk_eval_string(ctx, extras); duk_pop(ctx);

#ifdef _POSIX
	char fromBinary[] =
		"Object.defineProperty(Buffer, \"fromBinary\",\
		{\
			get: function()\
			{\
				return((function fromBinary(str)\
						{\
							var child = require('child_process').execFile('/usr/bin/iconv', ['iconv', '-c','-f', 'UTF-8', '-t', 'CP819']);\
							child.stdout.buf = Buffer.alloc(0);\
							child.stdout.on('data', function(c) { this.buf = Buffer.concat([this.buf, c]); });\
							child.stdin.write(str);\
							child.stderr.on('data', function(c) { });\
							child.stdin.end();\
							child.waitExit();\
							return(child.stdout.buf);\
						}));\
			}\
		});";
	duk_eval_string_noresult(ctx, fromBinary);

#endif

	// Polyfill Buffer.from()
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_from, DUK_VARARGS);		// [g][Buffer][func]
	duk_put_prop_string(ctx, -2, "from");											// [g][Buffer]
	duk_pop(ctx);																	// [g]

	// Polyfill Buffer.alloc() for Node Buffers)
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_alloc, DUK_VARARGS);		// [g][Buffer][func]
	duk_put_prop_string(ctx, -2, "alloc");											// [g][Buffer]
	duk_pop(ctx);																	// [g]


	// Polyfill Buffer.toString() for Node Buffers
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Buffer][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_toString, DUK_VARARGS);	// [g][Buffer][prototype][func]
	duk_put_prop_string(ctx, -2, "toString");										// [g][Buffer][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_randomFill, DUK_VARARGS);	// [g][Buffer][prototype][func]
	duk_put_prop_string(ctx, -2, "randomFill");										// [g][Buffer][prototype]
	duk_pop_2(ctx);																	// [g]
}
duk_ret_t ILibDuktape_Polyfills_String_startsWith(duk_context *ctx)
{
	duk_size_t tokenLen;
	char *token = Duktape_GetBuffer(ctx, 0, &tokenLen);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if (ILibString_StartsWith(buffer, (int)bufferLen, token, (int)tokenLen) != 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_Polyfills_String_endsWith(duk_context *ctx)
{
	duk_size_t tokenLen;
	char *token = Duktape_GetBuffer(ctx, 0, &tokenLen);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	
	if (ILibString_EndsWith(buffer, (int)bufferLen, token, (int)tokenLen) != 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_Polyfills_String_padStart(duk_context *ctx)
{
	int totalLen = (int)duk_require_int(ctx, 0);

	duk_size_t padcharLen;
	duk_size_t bufferLen;

	char *padchars;
	if (duk_get_top(ctx) > 1)
	{
		padchars = (char*)duk_get_lstring(ctx, 1, &padcharLen);
	}
	else
	{
		padchars = " ";
		padcharLen = 1;
	}

	duk_push_this(ctx);
	char *buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if ((int)bufferLen > totalLen)
	{
		duk_push_lstring(ctx, buffer, bufferLen);
		return(1);
	}
	else
	{
		duk_size_t needs = totalLen - bufferLen;

		duk_push_array(ctx);											// [array]
		while(needs > 0)
		{
			if (needs > padcharLen)
			{
				duk_push_string(ctx, padchars);							// [array][pad]
				duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));	// [array]
				needs -= padcharLen;
			}
			else
			{
				duk_push_lstring(ctx, padchars, needs);					// [array][pad]
				duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));	// [array]
				needs = 0;
			}
		}
		duk_push_lstring(ctx, buffer, bufferLen);						// [array][pad]
		duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));			// [array]
		duk_get_prop_string(ctx, -1, "join");							// [array][join]
		duk_swap_top(ctx, -2);											// [join][this]
		duk_push_string(ctx, "");										// [join][this]['']
		duk_call_method(ctx, 1);										// [result]
		return(1);
	}
}
duk_ret_t ILibDuktape_Polyfills_Array_includes(duk_context *ctx)
{
	duk_push_this(ctx);										// [array]
	uint32_t count = (uint32_t)duk_get_length(ctx, -1);
	uint32_t i;
	for (i = 0; i < count; ++i)
	{
		duk_get_prop_index(ctx, -1, (duk_uarridx_t)i);		// [array][val1]
		duk_dup(ctx, 0);									// [array][val1][val2]
		if (duk_equals(ctx, -2, -1))
		{
			duk_push_true(ctx);
			return(1);
		}
		else
		{
			duk_pop_2(ctx);									// [array]
		}
	}
	duk_push_false(ctx);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_partialIncludes(duk_context *ctx)
{
	duk_size_t inLen;
	char *inStr = (char*)duk_get_lstring(ctx, 0, &inLen);
	duk_push_this(ctx);										// [array]
	uint32_t count = (uint32_t)duk_get_length(ctx, -1);
	uint32_t i;
	duk_size_t tmpLen;
	char *tmp;
	for (i = 0; i < count; ++i)
	{
		tmp = Duktape_GetStringPropertyIndexValueEx(ctx, -1, i, "", &tmpLen);
		if (inLen > 0 && inLen <= tmpLen && strncmp(inStr, tmp, inLen) == 0)
		{
			duk_push_int(ctx, i);
			return(1);
		}
	}
	duk_push_int(ctx, -1);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_find(duk_context *ctx)
{
	duk_push_this(ctx);								// [array]
	duk_prepare_method_call(ctx, -1, "findIndex");	// [array][findIndex][this]
	duk_dup(ctx, 0);								// [array][findIndex][this][func]
	duk_call_method(ctx, 1);						// [array][result]
	if (duk_get_int(ctx, -1) == -1) { duk_push_undefined(ctx); return(1); }
	duk_get_prop(ctx, -2);							// [element]
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_findIndex(duk_context *ctx)
{
	duk_idx_t nargs = duk_get_top(ctx);
	duk_push_this(ctx);								// [array]

	duk_size_t sz = duk_get_length(ctx, -1);
	duk_uarridx_t i;

	for (i = 0; i < sz; ++i)
	{
		duk_dup(ctx, 0);							// [array][func]
		if (nargs > 1 && duk_is_function(ctx, 1))
		{
			duk_dup(ctx, 1);						// [array][func][this]
		}
		else
		{
			duk_push_this(ctx);						// [array][func][this]
		}
		duk_get_prop_index(ctx, -3, i);				// [array][func][this][element]
		duk_push_uint(ctx, i);						// [array][func][this][element][index]
		duk_push_this(ctx);							// [array][func][this][element][index][array]
		duk_call_method(ctx, 3);					// [array][ret]
		if (!duk_is_undefined(ctx, -1) && duk_is_boolean(ctx, -1) && duk_to_boolean(ctx, -1) != 0)
		{
			duk_push_uint(ctx, i);
			return(1);
		}
		duk_pop(ctx);								// [array]
	}
	duk_push_int(ctx, -1);
	return(1);
}
void ILibDuktape_Polyfills_Array(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Array");											// [Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [Array][proto]

	// Polyfill 'Array.includes'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "includes", ILibDuktape_Polyfills_Array_includes, 1, 0);

	// Polyfill 'Array.partialIncludes'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "partialIncludes", ILibDuktape_Polyfills_Array_partialIncludes, 1, 0);

	// Polyfill 'Array.find'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "find", ILibDuktape_Polyfills_Array_find, 1, 0);

	// Polyfill 'Array.findIndex'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "findIndex", ILibDuktape_Polyfills_Array_findIndex, DUK_VARARGS, 0);
	duk_pop_2(ctx);																	// ...
}
duk_ret_t ILibDuktape_Polyfills_String_splitEx(duk_context *ctx)
{
	duk_ret_t ret = 1;

	if (duk_is_null_or_undefined(ctx, 0))
	{
		duk_push_array(ctx);		// [array]
		duk_push_this(ctx);			// [array][string]
		duk_array_push(ctx, -2);	// [array]
	}
	else if (duk_is_string(ctx, 0))
	{
		const char *delim, *str;
		duk_size_t delimLen, strLen;

		duk_push_this(ctx);
		delim = duk_to_lstring(ctx, 0, &delimLen);
		str = duk_to_lstring(ctx, -1, &strLen);

		parser_result *pr = ILibParseStringAdv(str, 0, strLen, delim, delimLen);
		parser_result_field *f = pr->FirstResult;

		duk_push_array(ctx);
		while (f != NULL)
		{
			duk_push_lstring(ctx, f->data, f->datalength);
			duk_array_push(ctx, -2);
			f = f->NextResult;
		}

		ILibDestructParserResults(pr);
	}
	else
	{
		ret = ILibDuktape_Error(ctx, "Invalid Arguments");
	}
	return(ret);
}
void ILibDuktape_Polyfills_String(duk_context *ctx)
{
	// Polyfill 'String.startsWith'
	duk_get_prop_string(ctx, -1, "String");											// [string]
	duk_get_prop_string(ctx, -1, "prototype");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_startsWith, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "startsWith");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_endsWith, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "endsWith");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_padStart, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "padStart");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_splitEx, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "splitEx");										// [string][proto]
	duk_pop_2(ctx);
}
duk_ret_t ILibDuktape_Polyfills_Console_log(duk_context *ctx)
{
	int numargs = duk_get_top(ctx);
	int i, x;
	duk_size_t strLen;
	char *str;
	char *PREFIX = NULL;
	char *DESTINATION = NULL;
	duk_push_current_function(ctx);
	ILibDuktape_LogTypes logType = (ILibDuktape_LogTypes)Duktape_GetIntPropertyValue(ctx, -1, "logType", ILibDuktape_LogType_Normal);
	switch (logType)
	{
		case ILibDuktape_LogType_Warn:
			PREFIX = (char*)"WARNING: "; // LENGTH MUST BE <= 9
			DESTINATION = ILibDuktape_Console_WARN_Destination;
			break;
		case ILibDuktape_LogType_Error:
			PREFIX = (char*)"ERROR: "; // LENGTH MUST BE <= 9
			DESTINATION = ILibDuktape_Console_ERROR_Destination;
			break;
		case ILibDuktape_LogType_Info1:
		case ILibDuktape_LogType_Info2:
		case ILibDuktape_LogType_Info3:
			duk_push_this(ctx);
			i = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_Console_INFO_Level, 0);
			duk_pop(ctx);
			PREFIX = NULL;
			if (i >= (((int)logType + 1) - (int)ILibDuktape_LogType_Info1))
			{
				DESTINATION = ILibDuktape_Console_LOG_Destination;
			}
			else
			{
				return(0);
			}
			break;
		default:
			PREFIX = NULL;
			DESTINATION = ILibDuktape_Console_LOG_Destination;
			break;
	}
	duk_pop(ctx);

	// Calculate total length of string
	strLen = 0;
	strLen += snprintf(NULL, 0, "%s", PREFIX != NULL ? PREFIX : "");
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			strLen += snprintf(NULL, 0, "%s%s", (i == 0 ? "" : ", "), duk_require_string(ctx, i));
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				strLen += snprintf(NULL, 0, "%s", (i == 0 ? "{" : ", {"));
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					strLen += snprintf(NULL, 0, "%s%s: %s", ((propNum++ == 0) ? " " : ", "), (char*)duk_to_string(ctx, -2), (char*)duk_to_string(ctx, -1));
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				strLen += snprintf(NULL, 0, " }");
			}
			else
			{
				strLen += snprintf(NULL, 0, "%s%s", (i == 0 ? "" : ", "), duk_to_string(ctx, -1));
			}
		}
	}
	strLen += snprintf(NULL, 0, "\n");
	strLen += 1;

	str = Duktape_PushBuffer(ctx, strLen);
	x = 0;
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			x += sprintf_s(str + x, strLen - x, "%s%s", (i == 0 ? "" : ", "), duk_require_string(ctx, i));
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				x += sprintf_s(str+x, strLen - x, "%s", (i == 0 ? "{" : ", {"));
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					x += sprintf_s(str + x, strLen - x, "%s%s: %s", ((propNum++ == 0) ? " " : ", "), (char*)duk_to_string(ctx, -2), (char*)duk_to_string(ctx, -1));
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				x += sprintf_s(str + x, strLen - x, " }");
			}
			else
			{
				x += sprintf_s(str + x, strLen - x, "%s%s", (i == 0 ? "" : ", "), duk_to_string(ctx, -1));
			}
		}
	}
	x += sprintf_s(str + x, strLen - x, "\n");

	duk_push_this(ctx);		// [console]
	int dest = Duktape_GetIntPropertyValue(ctx, -1, DESTINATION, ILibDuktape_Console_DestinationFlags_StdOut);

	if ((dest & ILibDuktape_Console_DestinationFlags_StdOut) == ILibDuktape_Console_DestinationFlags_StdOut)
	{
#ifdef WIN32
		DWORD writeLen;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), (void*)str, x, &writeLen, NULL);
#else
		ignore_result(write(STDOUT_FILENO, str, x));
#endif
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_WebLog) == ILibDuktape_Console_DestinationFlags_WebLog)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(Duktape_GetChain(ctx)), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "%s", str);
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_ServerConsole) == ILibDuktape_Console_DestinationFlags_ServerConsole)
	{
		if (duk_peval_string(ctx, "require('MeshAgent');") == 0)
		{
			duk_get_prop_string(ctx, -1, "SendCommand");	// [console][agent][SendCommand]
			duk_swap_top(ctx, -2);							// [console][SendCommand][this]
			duk_push_object(ctx);							// [console][SendCommand][this][options]
			duk_push_string(ctx, "msg"); duk_put_prop_string(ctx, -2, "action");
			duk_push_string(ctx, "console"); duk_put_prop_string(ctx, -2, "type");
			duk_push_string(ctx, str); duk_put_prop_string(ctx, -2, "value");
			if (duk_has_prop_string(ctx, -4, ILibDuktape_Console_SessionID))
			{
				duk_get_prop_string(ctx, -4, ILibDuktape_Console_SessionID);
				duk_put_prop_string(ctx, -2, "sessionid");
			}
			duk_call_method(ctx, 1);
		}
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_LogFile) == ILibDuktape_Console_DestinationFlags_LogFile)
	{
		duk_size_t pathLen;
		char *path;
		char *tmp = (char*)ILibMemory_SmartAllocate(x + 32);
		int tmpx = ILibGetLocalTime(tmp + 1, (int)ILibMemory_Size(tmp) - 1) + 1;
		tmp[0] = '[';
		tmp[tmpx] = ']';
		tmp[tmpx + 1] = ':';
		tmp[tmpx + 2] = ' ';
		memcpy_s(tmp + tmpx + 3, ILibMemory_Size(tmp) - tmpx - 3, str, x);
		duk_eval_string(ctx, "require('fs');");
		duk_get_prop_string(ctx, -1, "writeFileSync");						// [fs][writeFileSync]
		duk_swap_top(ctx, -2);												// [writeFileSync][this]
		duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));			// [writeFileSync][this][process]
		duk_get_prop_string(ctx, -1, "execPath");							// [writeFileSync][this][process][execPath]
		path = (char*)duk_get_lstring(ctx, -1, &pathLen);
		if (path != NULL)
		{
			if (ILibString_EndsWithEx(path, (int)pathLen, ".exe", 4, 0))
			{
				duk_get_prop_string(ctx, -1, "substring");						// [writeFileSync][this][process][execPath][substring]
				duk_swap_top(ctx, -2);											// [writeFileSync][this][process][substring][this]
				duk_push_int(ctx, 0);											// [writeFileSync][this][process][substring][this][0]
				duk_push_int(ctx, (int)(pathLen - 4));							// [writeFileSync][this][process][substring][this][0][len]
				duk_call_method(ctx, 2);										// [writeFileSync][this][process][path]
			}
			duk_get_prop_string(ctx, -1, "concat");								// [writeFileSync][this][process][path][concat]
			duk_swap_top(ctx, -2);												// [writeFileSync][this][process][concat][this]
			duk_push_string(ctx, ".jlog");										// [writeFileSync][this][process][concat][this][.jlog]
			duk_call_method(ctx, 1);											// [writeFileSync][this][process][logPath]
			duk_remove(ctx, -2);												// [writeFileSync][this][logPath]
			duk_push_string(ctx, tmp);											// [writeFileSync][this][logPath][log]
			duk_push_object(ctx);												// [writeFileSync][this][logPath][log][options]
			duk_push_string(ctx, "a"); duk_put_prop_string(ctx, -2, "flags");
			duk_pcall_method(ctx, 3);
		}
		ILibMemory_Free(tmp);
	}
	return 0;
}
duk_ret_t ILibDuktape_Polyfills_Console_enableWebLog(duk_context *ctx)
{
#ifdef _REMOTELOGGING
	void *chain = Duktape_GetChain(ctx);
	int port = duk_require_int(ctx, 0);
	duk_size_t pLen;
	if (duk_peval_string(ctx, "process.argv0") != 0) { return(ILibDuktape_Error(ctx, "console.enableWebLog(): Couldn't fetch argv0")); }
	char *p = (char*)duk_get_lstring(ctx, -1, &pLen);
	if (ILibString_EndsWith(p, (int)pLen, ".js", 3) != 0)
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), p, pLen - 3);
		sprintf_s(ILibScratchPad2 + (pLen - 3), sizeof(ILibScratchPad2) - 3, ".wlg");
	}
	else if (ILibString_EndsWith(p, (int)pLen, ".exe", 3) != 0)
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), p, pLen - 4);
		sprintf_s(ILibScratchPad2 + (pLen - 3), sizeof(ILibScratchPad2) - 4, ".wlg");
	}
	else
	{
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s.wlg", p);
	}
	ILibStartDefaultLoggerEx(chain, (unsigned short)port, ILibScratchPad2);
#endif
	return (0);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayStreamPipe_getter(duk_context *ctx)
{
	duk_push_int(ctx, g_displayStreamPipeMessages);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayStreamPipe_setter(duk_context *ctx)
{
	g_displayStreamPipeMessages = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayFinalizer_getter(duk_context *ctx)
{
	duk_push_int(ctx, g_displayFinalizerMessages);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayFinalizer_setter(duk_context *ctx)
{
	g_displayFinalizerMessages = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_logRefCount(duk_context *ctx)
{
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "console");	// [g][console]
	duk_get_prop_string(ctx, -1, "log");									// [g][console][log]
	duk_swap_top(ctx, -2);													// [g][log][this]
	duk_push_sprintf(ctx, "Reference Count => %s[%p]:%d\n", Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_OBJID, "UNKNOWN"), duk_require_heapptr(ctx, 0), ILibDuktape_GetReferenceCount(ctx, 0) - 1);
	duk_call_method(ctx, 1);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_setDestination(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int dest = duk_require_int(ctx, 0);

	duk_push_this(ctx);						// console
	if ((dest & ILibDuktape_Console_DestinationFlags_ServerConsole) == ILibDuktape_Console_DestinationFlags_ServerConsole)
	{
		// Mesh Server Console
		if (duk_peval_string(ctx, "require('MeshAgent');") != 0) { return(ILibDuktape_Error(ctx, "Unable to set destination to Mesh Console ")); }
		duk_pop(ctx);
		if (nargs > 1)
		{
			duk_dup(ctx, 1);
			duk_put_prop_string(ctx, -2, ILibDuktape_Console_SessionID);
		}
		else
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_Console_SessionID);
		}
	}
	duk_dup(ctx, 0);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_Destination);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_setInfoLevel(duk_context *ctx)
{
	int val = duk_require_int(ctx, 0);
	if (val < 0) { return(ILibDuktape_Error(ctx, "Invalid Info Level: %d", val)); }

	duk_push_this(ctx);
	duk_push_int(ctx, val);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_INFO_Level);

	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_getInfoLevel(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_Console_INFO_Level);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_setInfoMask(duk_context *ctx)
{
	ILIBLOGMESSAGEX2_SetMask(duk_require_uint(ctx, 0));
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_canonical_get(duk_context *ctx)
{
#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	duk_push_boolean(ctx, (mode & ENABLE_LINE_INPUT) == ENABLE_LINE_INPUT);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);
	duk_push_boolean(ctx, (term.c_lflag & ICANON) == ICANON);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_canonical_set(duk_context *ctx)
{
	int val = duk_require_boolean(ctx, 0) ? 1 : 0;

#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	if (val == 0)
	{
		mode = mode & 0xFFFFFFFD;
	}
	else
	{
		mode |= ENABLE_LINE_INPUT;
	}
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);

	if (val == 0)
	{
		term.c_lflag &= ~ICANON;
	}
	else
	{
		term.c_lflag |= ICANON;
	}
	tcsetattr(fileno(stdin), 0, &term);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_echo_get(duk_context *ctx)
{
#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	duk_push_boolean(ctx, (mode & ENABLE_ECHO_INPUT) == ENABLE_ECHO_INPUT);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);
	duk_push_boolean(ctx, (term.c_lflag & ECHO) == ECHO);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_echo_set(duk_context *ctx)
{
	int val = duk_require_boolean(ctx, 0) ? 1 : 0;

#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	if (val == 0)
	{
		mode = mode & 0xFFFFFFFB;
	}
	else
	{
		mode |= ENABLE_ECHO_INPUT;
	}
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);

	if (val == 0)
	{
		term.c_lflag &= ~ECHO;
	}
	else
	{
		term.c_lflag |= ECHO;
	}
	tcsetattr(fileno(stdin), 0, &term);
#endif
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_rawLog(duk_context *ctx)
{
	char *val = (char*)duk_require_string(ctx, 0);
	ILIBLOGMESSAGEX("%s", val);
	return(0);
}
void ILibDuktape_Polyfills_Console(duk_context *ctx)
{
	// Polyfill console.log()
#ifdef WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif

	if (duk_has_prop_string(ctx, -1, "console"))
	{
		duk_get_prop_string(ctx, -1, "console");									// [g][console]
	}
	else
	{
		duk_push_object(ctx);														// [g][console]
		duk_dup(ctx, -1);															// [g][console][console]
		duk_put_prop_string(ctx, -3, "console");									// [g][console]
	}

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Normal, "log", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Warn, "warn", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Error, "error", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info1, "info1", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info2, "info2", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info3, "info3", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "rawLog", ILibDuktape_Polyfills_Console_rawLog, 1);

	ILibDuktape_CreateInstanceMethod(ctx, "enableWebLog", ILibDuktape_Polyfills_Console_enableWebLog, 1);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "displayStreamPipeMessages", ILibDuktape_Polyfills_Console_displayStreamPipe_getter, ILibDuktape_Polyfills_Console_displayStreamPipe_setter);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "displayFinalizerMessages", ILibDuktape_Polyfills_Console_displayFinalizer_getter, ILibDuktape_Polyfills_Console_displayFinalizer_setter);
	ILibDuktape_CreateInstanceMethod(ctx, "logReferenceCount", ILibDuktape_Polyfills_Console_logRefCount, 1);
	
	ILibDuktape_CreateInstanceMethod(ctx, "setDestination", ILibDuktape_Polyfills_Console_setDestination, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoLevel", ILibDuktape_Polyfills_Console_setInfoLevel, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "getInfoLevel", ILibDuktape_Polyfills_Console_getInfoLevel, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoMask", ILibDuktape_Polyfills_Console_setInfoMask, 1);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "echo", ILibDuktape_Polyfills_Console_echo_get, ILibDuktape_Polyfills_Console_echo_set);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "canonical", ILibDuktape_Polyfills_Console_canonical_get, ILibDuktape_Polyfills_Console_canonical_set);

	duk_push_object(ctx);
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_DISABLED); duk_put_prop_string(ctx, -2, "DISABLED");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut); duk_put_prop_string(ctx, -2, "STDOUT");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_ServerConsole); duk_put_prop_string(ctx, -2, "SERVERCONSOLE");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_WebLog); duk_put_prop_string(ctx, -2, "WEBLOG");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_LogFile); duk_put_prop_string(ctx, -2, "LOGFILE");
	ILibDuktape_CreateReadonlyProperty(ctx, "Destinations");

	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut | ILibDuktape_Console_DestinationFlags_LogFile);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_ERROR_Destination);

	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut | ILibDuktape_Console_DestinationFlags_LogFile);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_WARN_Destination);

	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_Console_INFO_Level);

	duk_pop(ctx);																	// [g]
}
duk_ret_t ILibDuktape_ntohl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohl(((unsigned int*)(buffer + offset))[0]));
	return 1;
}
duk_ret_t ILibDuktape_ntohs(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < 2 + offset) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohs(((unsigned short*)(buffer + offset))[0]));
	return 1;
}
duk_ret_t ILibDuktape_htonl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	((unsigned int*)(buffer + offset))[0] = htonl(val);
	return 0;
}
duk_ret_t ILibDuktape_htons(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (2 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	((unsigned short*)(buffer + offset))[0] = htons(val);
	return 0;
}
void ILibDuktape_Polyfills_byte_ordering(duk_context *ctx)
{
	ILibDuktape_CreateInstanceMethod(ctx, "ntohl", ILibDuktape_ntohl, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "ntohs", ILibDuktape_ntohs, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "htonl", ILibDuktape_htonl, 3);
	ILibDuktape_CreateInstanceMethod(ctx, "htons", ILibDuktape_htons, 3);
}

typedef enum ILibDuktape_Timer_Type
{
	ILibDuktape_Timer_Type_TIMEOUT = 0,
	ILibDuktape_Timer_Type_INTERVAL = 1,
	ILibDuktape_Timer_Type_IMMEDIATE = 2
}ILibDuktape_Timer_Type;
typedef struct ILibDuktape_Timer
{
	duk_context *ctx;
	void *object;
	void *callback;
	void *args;
	int timeout;
	ILibDuktape_Timer_Type timerType;
}ILibDuktape_Timer;

duk_ret_t ILibDuktape_Polyfills_timer_finalizer(duk_context *ctx)
{
	// Make sure we remove any timers just in case, so we don't leak resources
	ILibDuktape_Timer *ptrs;
	if (duk_has_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs);
		if (duk_has_prop_string(ctx, 0, "\xFF_callback"))
		{
			duk_del_prop_string(ctx, 0, "\xFF_callback");
		}
		if (duk_has_prop_string(ctx, 0, "\xFF_argArray"))
		{
			duk_del_prop_string(ctx, 0, "\xFF_argArray");
		}
		ptrs = (ILibDuktape_Timer*)Duktape_GetBuffer(ctx, -1, NULL);

		ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs);
	}

	duk_eval_string(ctx, "require('events')");			// [events]
	duk_prepare_method_call(ctx, -1, "deleteProperty");	// [events][deleteProperty][this]
	duk_push_this(ctx);									// [events][deleteProperty][this][timer]
	duk_prepare_method_call(ctx, -4, "hiddenProperties");//[events][deleteProperty][this][timer][hidden][this]
	duk_push_this(ctx);									// [events][deleteProperty][this][timer][hidden][this][timer]
	duk_call_method(ctx, 1);							// [events][deleteProperty][this][timer][array]
	duk_call_method(ctx, 2);							// [events][ret]
	return 0;
}
void ILibDuktape_Polyfills_timer_elapsed(void *obj)
{
	ILibDuktape_Timer *ptrs = (ILibDuktape_Timer*)obj;
	int argCount, i;
	char *funcName;

	if (!ILibMemory_CanaryOK(ptrs)) { return; }
	
	duk_context *ctx = ptrs->ctx;
	if (duk_check_stack(ctx, 3) == 0) { return; }

	duk_push_heapptr(ctx, ptrs->callback);				// [func]
	funcName = Duktape_GetStringPropertyValue(ctx, -1, "name", "unknown_method");
	duk_push_heapptr(ctx, ptrs->object);				// [func][this]
	duk_push_heapptr(ctx, ptrs->args);					// [func][this][argArray]

	if (ptrs->timerType == ILibDuktape_Timer_Type_INTERVAL)
	{
		char *metadata = ILibLifeTime_GetCurrentTriggeredMetadata(ILibGetBaseTimer(duk_ctx_chain(ctx)));
		ILibLifeTime_AddEx3(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL, metadata);
	}
	else
	{
		if (ptrs->timerType == ILibDuktape_Timer_Type_IMMEDIATE)
		{
			duk_push_heap_stash(ctx);
			duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
			duk_pop(ctx);
		}

		duk_del_prop_string(ctx, -2, "\xFF_callback");
		duk_del_prop_string(ctx, -2, "\xFF_argArray");
		duk_del_prop_string(ctx, -2, ILibDuktape_Timer_Ptrs);
	}

	argCount = (int)duk_get_length(ctx, -1);
	for (i = 0; i < argCount; ++i)
	{
		duk_get_prop_index(ctx, -1, i);					// [func][this][argArray][arg]
		duk_swap_top(ctx, -2);							// [func][this][arg][argArray]
	}
	duk_pop(ctx);										// [func][this][...arg...]
	if (duk_pcall_method(ctx, argCount) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "timers.onElapsed() callback handler on '%s()' ", funcName); }
	duk_pop(ctx);										// ...
}
duk_ret_t ILibDuktape_Polyfills_Timer_Metadata(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibLifeTime_Token token = (ILibLifeTime_Token)Duktape_GetPointerProperty(ctx, -1, "\xFF_token");
	if (token != NULL)
	{
		duk_size_t metadataLen;
		char *metadata = (char*)duk_require_lstring(ctx, 0, &metadataLen);
		ILibLifeTime_SetMetadata(token, metadata, metadataLen);
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_timer_set(duk_context *ctx)
{
	char *metadata = NULL;
	int nargs = duk_get_top(ctx);
	ILibDuktape_Timer *ptrs;
	ILibDuktape_Timer_Type timerType;
	void *chain = Duktape_GetChain(ctx);
	int argx;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "type");
	timerType = (ILibDuktape_Timer_Type)duk_get_int(ctx, -1);

	duk_push_object(ctx);																	//[retVal]
	switch (timerType)
	{
	case ILibDuktape_Timer_Type_IMMEDIATE:
		ILibDuktape_WriteID(ctx, "Timers.immediate");	
		metadata = "setImmediate()";
		// We're only saving a reference for immediates
		duk_push_heap_stash(ctx);															//[retVal][stash]
		duk_dup(ctx, -2);																	//[retVal][stash][immediate]
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));		//[retVal][stash]
		duk_pop(ctx);																		//[retVal]
		break;
	case ILibDuktape_Timer_Type_INTERVAL:
		ILibDuktape_WriteID(ctx, "Timers.interval");
		metadata = "setInterval()";
		break;
	case ILibDuktape_Timer_Type_TIMEOUT:
		ILibDuktape_WriteID(ctx, "Timers.timeout");
		metadata = "setTimeout()";
		break;
	}
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Polyfills_timer_finalizer);
	
	ptrs = (ILibDuktape_Timer*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_Timer));	//[retVal][ptrs]
	duk_put_prop_string(ctx, -2, ILibDuktape_Timer_Ptrs);							//[retVal]

	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->timerType = timerType;
	ptrs->timeout = timerType == ILibDuktape_Timer_Type_IMMEDIATE ? 0 : (int)duk_require_int(ctx, 1);
	ptrs->callback = duk_require_heapptr(ctx, 0);

	duk_push_array(ctx);																			//[retVal][argArray]
	for (argx = ILibDuktape_Timer_Type_IMMEDIATE == timerType ? 1 : 2; argx < nargs; ++argx)
	{
		duk_dup(ctx, argx);																			//[retVal][argArray][arg]
		duk_put_prop_index(ctx, -2, argx - (ILibDuktape_Timer_Type_IMMEDIATE == timerType ? 1 : 2));//[retVal][argArray]
	}
	ptrs->args = duk_get_heapptr(ctx, -1);															//[retVal]
	duk_put_prop_string(ctx, -2, "\xFF_argArray");

	duk_dup(ctx, 0);																				//[retVal][callback]
	duk_put_prop_string(ctx, -2, "\xFF_callback");													//[retVal]

	duk_push_pointer(
		ctx,
		ILibLifeTime_AddEx3(ILibGetBaseTimer(chain), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL, metadata));
	duk_put_prop_string(ctx, -2, "\xFF_token");
	ILibDuktape_CreateEventWithSetterEx(ctx, "metadata", ILibDuktape_Polyfills_Timer_Metadata);
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_timer_clear(duk_context *ctx)
{
	ILibDuktape_Timer *ptrs;
	ILibDuktape_Timer_Type timerType;
	
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "type");
	timerType = (ILibDuktape_Timer_Type)duk_get_int(ctx, -1);

	if(!duk_has_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs)) 
	{
		switch (timerType)
		{
			case ILibDuktape_Timer_Type_TIMEOUT:
				return(ILibDuktape_Error(ctx, "timers.clearTimeout(): Invalid Parameter"));
			case ILibDuktape_Timer_Type_INTERVAL:
				return(ILibDuktape_Error(ctx, "timers.clearInterval(): Invalid Parameter"));
			case ILibDuktape_Timer_Type_IMMEDIATE:
				return(ILibDuktape_Error(ctx, "timers.clearImmediate(): Invalid Parameter"));
		}
	}

	duk_dup(ctx, 0);
	duk_del_prop_string(ctx, -1, "\xFF_argArray");

	duk_get_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs);
	ptrs = (ILibDuktape_Timer*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ptrs->timerType == ILibDuktape_Timer_Type_IMMEDIATE)
	{
		duk_push_heap_stash(ctx);
		duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
		duk_pop(ctx);
	}

	ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs);
	return 0;
}
void ILibDuktape_Polyfills_timer(duk_context *ctx)
{
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_TIMEOUT, "setTimeout", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_INTERVAL, "setInterval", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_IMMEDIATE, "setImmediate", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_TIMEOUT, "clearTimeout", ILibDuktape_Polyfills_timer_clear, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_INTERVAL, "clearInterval", ILibDuktape_Polyfills_timer_clear, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_IMMEDIATE, "clearImmediate", ILibDuktape_Polyfills_timer_clear, 1);
}
duk_ret_t ILibDuktape_Polyfills_getJSModule(duk_context *ctx)
{
	if (ILibDuktape_ModSearch_GetJSModule(ctx, (char*)duk_require_string(ctx, 0)) == 0)
	{
		return(ILibDuktape_Error(ctx, "getJSModule(): (%s) not found", (char*)duk_require_string(ctx, 0)));
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_getJSModuleDate(duk_context *ctx)
{
	duk_push_uint(ctx, ILibDuktape_ModSearch_GetJSModuleDate(ctx, (char*)duk_require_string(ctx, 0)));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_addModule(duk_context *ctx)
{
	int narg = duk_get_top(ctx);
	duk_size_t moduleLen;
	duk_size_t moduleNameLen;
	char *module = (char*)Duktape_GetBuffer(ctx, 1, &moduleLen);
	char *moduleName = (char*)Duktape_GetBuffer(ctx, 0, &moduleNameLen);
	char *mtime = narg > 2 ? (char*)duk_require_string(ctx, 2) : NULL;
	int add = 0;

	ILibDuktape_Polyfills_getJSModuleDate(ctx);								// [existing]
	uint32_t update = 0;
	uint32_t existing = duk_get_uint(ctx, -1);
	duk_pop(ctx);															// ...

	if (mtime != NULL)
	{
		// Check the timestamps
		duk_push_sprintf(ctx, "(new Date('%s')).getTime()/1000", mtime);	// [str]
		duk_eval(ctx);														// [new]
		update = duk_get_uint(ctx, -1);
		duk_pop(ctx);														// ...
	}
	if ((update > existing) || (update == existing && update == 0)) { add = 1; }

	if (add != 0)
	{
		if (ILibDuktape_ModSearch_IsRequired(ctx, moduleName, (int)moduleNameLen) != 0)
		{
			// Module is already cached, so we need to do some magic
			duk_push_sprintf(ctx, "if(global._legacyrequire==null) {global._legacyrequire = global.require; global.require = global._altrequire;}");
			duk_eval_noresult(ctx);
		}
		if (ILibDuktape_ModSearch_AddModuleEx(ctx, moduleName, module, (int)moduleLen, mtime) != 0)
		{
			return(ILibDuktape_Error(ctx, "Cannot add module: %s", moduleName));
		}
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addCompressedModule_dataSink(duk_context *ctx)
{
	duk_push_this(ctx);								// [stream]
	if (!duk_has_prop_string(ctx, -1, "_buffer"))
	{
		duk_push_array(ctx);						// [stream][array]
		duk_dup(ctx, 0);							// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_buffer_concat(ctx);						// [stream][buffer]
		duk_put_prop_string(ctx, -2, "_buffer");	// [stream]
	}
	else
	{
		duk_push_array(ctx);						// [stream][array]
		duk_get_prop_string(ctx, -2, "_buffer");	// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_dup(ctx, 0);							// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_buffer_concat(ctx);						// [stream][buffer]
		duk_put_prop_string(ctx, -2, "_buffer");	// [stream]
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addCompressedModule(duk_context *ctx)
{
	int narg = duk_get_top(ctx);
	duk_eval_string(ctx, "require('compressed-stream').createDecompressor();");
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_FinalizerDebugMessage);
	void *decoder = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "data", ILibDuktape_Polyfills_addCompressedModule_dataSink);

	duk_dup(ctx, -1);						// [stream]
	duk_get_prop_string(ctx, -1, "end");	// [stream][end]
	duk_swap_top(ctx, -2);					// [end][this]
	duk_dup(ctx, 1);						// [end][this][buffer]
	if (duk_pcall_method(ctx, 1) == 0)
	{
		duk_push_heapptr(ctx, decoder);				// [stream]
		duk_get_prop_string(ctx, -1, "_buffer");	// [stream][buffer]
		duk_get_prop_string(ctx, -1, "toString");	// [stream][buffer][toString]
		duk_swap_top(ctx, -2);						// [stream][toString][this]
		duk_call_method(ctx, 0);					// [stream][decodedString]
		duk_push_global_object(ctx);				// [stream][decodedString][global]
		duk_get_prop_string(ctx, -1, "addModule");	// [stream][decodedString][global][addModule]
		duk_swap_top(ctx, -2);						// [stream][decodedString][addModule][this]
		duk_dup(ctx, 0);							// [stream][decodedString][addModule][this][name]
		duk_dup(ctx, -4);							// [stream][decodedString][addModule][this][name][string]
		if (narg > 2) { duk_dup(ctx, 2); }
		duk_pcall_method(ctx, narg);
	}

	duk_push_heapptr(ctx, decoder);							// [stream]
	duk_prepare_method_call(ctx, -1, "removeAllListeners");	// [stream][remove][this]
	duk_pcall_method(ctx, 0);

	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addModuleObject(duk_context *ctx)
{
	void *module = duk_require_heapptr(ctx, 1);
	char *moduleName = (char*)duk_require_string(ctx, 0);

	ILibDuktape_ModSearch_AddModuleObject(ctx, moduleName, module);
	return(0);
}
duk_ret_t ILibDuktape_Queue_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_Queue_Ptr);
	ILibQueue_Destroy((ILibQueue)duk_get_pointer(ctx, -1));
	return(0);
}
duk_ret_t ILibDuktape_Queue_EnQueue(duk_context *ctx)
{
	ILibQueue Q;
	int i;
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																// [queue]
	duk_get_prop_string(ctx, -1, ILibDuktape_Queue_Ptr);							// [queue][ptr]
	Q = (ILibQueue)duk_get_pointer(ctx, -1);
	duk_pop(ctx);																	// [queue]

	ILibDuktape_Push_ObjectStash(ctx);												// [queue][stash]
	duk_push_array(ctx);															// [queue][stash][array]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);															// [queue][stash][array][arg]
		duk_put_prop_index(ctx, -2, i);												// [queue][stash][array]
	}
	ILibQueue_EnQueue(Q, duk_get_heapptr(ctx, -1));
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));	// [queue][stash]
	return(0);
}
duk_ret_t ILibDuktape_Queue_DeQueue(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "peek");
	int peek = duk_get_int(ctx, -1);

	duk_push_this(ctx);										// [Q]
	duk_get_prop_string(ctx, -1, ILibDuktape_Queue_Ptr);	// [Q][ptr]
	ILibQueue Q = (ILibQueue)duk_get_pointer(ctx, -1);
	void *h = peek == 0 ? ILibQueue_DeQueue(Q) : ILibQueue_PeekQueue(Q);
	if (h == NULL) { return(ILibDuktape_Error(ctx, "Queue is empty")); }
	duk_pop(ctx);											// [Q]
	ILibDuktape_Push_ObjectStash(ctx);						// [Q][stash]
	duk_push_heapptr(ctx, h);								// [Q][stash][array]
	int length = (int)duk_get_length(ctx, -1);
	int i;
	for (i = 0; i < length; ++i)
	{
		duk_get_prop_index(ctx, -i - 1, i);				   // [Q][stash][array][args]
	}
	if (peek == 0) { duk_del_prop_string(ctx, -length - 2, Duktape_GetStashKey(h)); }
	return(length);
}
duk_ret_t ILibDuktape_Queue_isEmpty(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_push_boolean(ctx, ILibQueue_IsEmpty((ILibQueue)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Queue_Ptr)));
	return(1);
}
duk_ret_t ILibDuktape_Queue_new(duk_context *ctx)
{
	duk_push_object(ctx);									// [queue]
	duk_push_pointer(ctx, ILibQueue_Create());				// [queue][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_Queue_Ptr);	// [queue]

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Queue_Finalizer);
	ILibDuktape_CreateInstanceMethod(ctx, "enQueue", ILibDuktape_Queue_EnQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "peek", 0, "deQueue", ILibDuktape_Queue_DeQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "peek", 1, "peekQueue", ILibDuktape_Queue_DeQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "isEmpty", ILibDuktape_Queue_isEmpty, 0);

	return(1);
}
void ILibDuktape_Queue_Push(duk_context *ctx, void* chain)
{
	duk_push_c_function(ctx, ILibDuktape_Queue_new, 0);
}

typedef struct ILibDuktape_DynamicBuffer_data
{
	int start;
	int end;
	int unshiftBytes;
	char *buffer;
	int bufferLen;
}ILibDuktape_DynamicBuffer_data;

typedef struct ILibDuktape_DynamicBuffer_ContextSwitchData
{
	void *chain;
	void *heapptr;
	ILibDuktape_DuplexStream *stream;
	ILibDuktape_DynamicBuffer_data *data;
	int bufferLen;
	char buffer[];
}ILibDuktape_DynamicBuffer_ContextSwitchData;

ILibTransport_DoneState ILibDuktape_DynamicBuffer_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user);
void ILibDuktape_DynamicBuffer_WriteSink_ChainThread(void *chain, void *user)
{
	ILibDuktape_DynamicBuffer_ContextSwitchData *data = (ILibDuktape_DynamicBuffer_ContextSwitchData*)user;
	if(ILibMemory_CanaryOK(data->stream))
	{
		ILibDuktape_DynamicBuffer_WriteSink(data->stream, data->buffer, data->bufferLen, data->data);
		ILibDuktape_DuplexStream_Ready(data->stream);
	}
	free(user);
}
ILibTransport_DoneState ILibDuktape_DynamicBuffer_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)user;
	if (ILibIsRunningOnChainThread(stream->readableStream->chain) == 0)
	{
		ILibDuktape_DynamicBuffer_ContextSwitchData *tmp = (ILibDuktape_DynamicBuffer_ContextSwitchData*)ILibMemory_Allocate(sizeof(ILibDuktape_DynamicBuffer_ContextSwitchData) + bufferLen, 0, NULL, NULL);
		tmp->chain = stream->readableStream->chain;
		tmp->heapptr = stream->ParentObject;
		tmp->stream = stream;
		tmp->data = data;
		tmp->bufferLen = bufferLen;
		memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen);
		Duktape_RunOnEventLoop(tmp->chain, duk_ctx_nonce(stream->readableStream->ctx), stream->readableStream->ctx, ILibDuktape_DynamicBuffer_WriteSink_ChainThread, NULL, tmp);
		return(ILibTransport_DoneState_INCOMPLETE);
	}


	if ((data->bufferLen - data->start - data->end) < bufferLen)
	{
		if (data->end > 0)
		{
			// Move the buffer first
			memmove_s(data->buffer, data->bufferLen, data->buffer + data->start, data->end);
			data->start = 0;
		}
		if ((data->bufferLen - data->end) < bufferLen)
		{
			// Need to resize buffer first
			int tmpSize = data->bufferLen;
			while ((tmpSize - data->end) < bufferLen)
			{
				tmpSize += 4096;
			}
			if ((data->buffer = (char*)realloc(data->buffer, tmpSize)) == NULL) { ILIBCRITICALEXIT(254); }
			data->bufferLen = tmpSize;
		}
	}


	memcpy_s(data->buffer + data->start + data->end, data->bufferLen - data->start - data->end, buffer, bufferLen);
	data->end += bufferLen;

	int unshifted = 0;
	do
	{
		duk_push_heapptr(stream->readableStream->ctx, stream->ParentObject);		// [ds]
		duk_get_prop_string(stream->readableStream->ctx, -1, "emit");				// [ds][emit]
		duk_swap_top(stream->readableStream->ctx, -2);								// [emit][this]
		duk_push_string(stream->readableStream->ctx, "readable");					// [emit][this][readable]
		if (duk_pcall_method(stream->readableStream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->readableStream->ctx, "DynamicBuffer.WriteSink => readable(): "); }
		duk_pop(stream->readableStream->ctx);										// ...

		ILibDuktape_DuplexStream_WriteData(stream, data->buffer + data->start, data->end);
		if (data->unshiftBytes == 0)
		{
			// All the data was consumed
			data->start = data->end = 0;
		}
		else
		{
			unshifted = (data->end - data->unshiftBytes);
			if (unshifted > 0)
			{
				data->start += unshifted;
				data->end = data->unshiftBytes;
				data->unshiftBytes = 0;
			}
		}
	} while (unshifted != 0);

	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_DynamicBuffer_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_DuplexStream_WriteEnd(stream);
}
duk_ret_t ILibDuktape_DynamicBuffer_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, "\xFF_buffer");
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	free(data->buffer);
	return(0);
}

int ILibDuktape_DynamicBuffer_unshift(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)user;
	data->unshiftBytes = unshiftBytes;
	return(unshiftBytes);
}
duk_ret_t ILibDuktape_DynamicBuffer_read(duk_context *ctx)
{
	ILibDuktape_DynamicBuffer_data *data;
	duk_push_this(ctx);															// [DynamicBuffer]
	duk_get_prop_string(ctx, -1, "\xFF_buffer");								// [DynamicBuffer][buffer]
	data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_push_external_buffer(ctx);												// [DynamicBuffer][buffer][extBuffer]
	duk_config_buffer(ctx, -1, data->buffer + data->start, data->bufferLen - (data->start + data->end));
	duk_push_buffer_object(ctx, -1, 0, data->bufferLen - (data->start + data->end), DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}
duk_ret_t ILibDuktape_DynamicBuffer_new(duk_context *ctx)
{
	ILibDuktape_DynamicBuffer_data *data;
	int initSize = 4096;
	if (duk_get_top(ctx) != 0)
	{
		initSize = duk_require_int(ctx, 0);
	}

	duk_push_object(ctx);					// [stream]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_DynamicBuffer_data));
	data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(data, 0, sizeof(ILibDuktape_DynamicBuffer_data));
	duk_put_prop_string(ctx, -2, "\xFF_buffer");

	data->bufferLen = initSize;
	data->buffer = (char*)malloc(initSize);

	ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_DynamicBuffer_WriteSink, ILibDuktape_DynamicBuffer_EndSink, NULL, NULL, ILibDuktape_DynamicBuffer_unshift, data);
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "readable");
	ILibDuktape_CreateInstanceMethod(ctx, "read", ILibDuktape_DynamicBuffer_read, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DynamicBuffer_Finalizer);

	return(1);
}

void ILibDuktape_DynamicBuffer_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_DynamicBuffer_new, DUK_VARARGS);
}

duk_ret_t ILibDuktape_Polyfills_debugCrash(duk_context *ctx)
{
	void *p = NULL;
	((int*)p)[0] = 55;
	return(0);
}


void ILibDuktape_Stream_PauseSink(struct ILibDuktape_readableStream *sender, void *user)
{
}
void ILibDuktape_Stream_ResumeSink(struct ILibDuktape_readableStream *sender, void *user)
{
	int skip = 0;
	duk_size_t bufferLen;

	duk_push_heapptr(sender->ctx, sender->object);			// [stream]
	void *func = Duktape_GetHeapptrProperty(sender->ctx, -1, "_read");
	duk_pop(sender->ctx);									// ...

	while (func != NULL && sender->paused == 0)
	{
		duk_push_heapptr(sender->ctx, sender->object);									// [this]
		if (!skip && duk_has_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer))
		{
			duk_get_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);			// [this][buffer]
			if ((bufferLen = duk_get_length(sender->ctx, -1)) > 0)
			{
				// Buffer is not empty, so we need to 'PUSH' it
				duk_get_prop_string(sender->ctx, -2, "push");							// [this][buffer][push]
				duk_dup(sender->ctx, -3);												// [this][buffer][push][this]
				duk_dup(sender->ctx, -3);												// [this][buffer][push][this][buffer]
				duk_remove(sender->ctx, -4);											// [this][push][this][buffer]
				duk_call_method(sender->ctx, 1);										// [this][boolean]
				sender->paused = !duk_get_boolean(sender->ctx, -1);
				duk_pop(sender->ctx);													// [this]

				if (duk_has_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer))
				{
					duk_get_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);	// [this][buffer]
					if (duk_get_length(sender->ctx, -1) == bufferLen)
					{
						// All the data was unshifted
						skip = !sender->paused;					
					}
					duk_pop(sender->ctx);												// [this]
				}
				duk_pop(sender->ctx);													// ...
			}
			else
			{
				// Buffer is empty
				duk_pop(sender->ctx);													// [this]
				duk_del_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);
				duk_pop(sender->ctx);													// ...
			}
		}
		else
		{
			// We need to 'read' more data
			duk_push_heapptr(sender->ctx, func);										// [this][read]
			duk_swap_top(sender->ctx, -2);												// [read][this]
			if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(sender->ctx); duk_pop(sender->ctx); break; }
			//																			// [buffer]
			if (duk_is_null_or_undefined(sender->ctx, -1))
			{
				duk_pop(sender->ctx);
				break;
			}
			duk_push_heapptr(sender->ctx, sender->object);								// [buffer][this]
			duk_swap_top(sender->ctx, -2);												// [this][buffer]
			if (duk_has_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer))
			{
				duk_push_global_object(sender->ctx);									// [this][buffer][g]
				duk_get_prop_string(sender->ctx, -1, "Buffer");							// [this][buffer][g][Buffer]
				duk_remove(sender->ctx, -2);											// [this][buffer][Buffer]
				duk_get_prop_string(sender->ctx, -1, "concat");							// [this][buffer][Buffer][concat]
				duk_swap_top(sender->ctx, -2);											// [this][buffer][concat][this]
				duk_push_array(sender->ctx);											// [this][buffer][concat][this][Array]
				duk_get_prop_string(sender->ctx, -1, "push");							// [this][buffer][concat][this][Array][push]
				duk_dup(sender->ctx, -2);												// [this][buffer][concat][this][Array][push][this]
				duk_get_prop_string(sender->ctx, -7, ILibDuktape_Stream_Buffer);		// [this][buffer][concat][this][Array][push][this][buffer]
				duk_call_method(sender->ctx, 1); duk_pop(sender->ctx);					// [this][buffer][concat][this][Array]
				duk_get_prop_string(sender->ctx, -1, "push");							// [this][buffer][concat][this][Array][push]
				duk_dup(sender->ctx, -2);												// [this][buffer][concat][this][Array][push][this]
				duk_dup(sender->ctx, -6);												// [this][buffer][concat][this][Array][push][this][buffer]
				duk_remove(sender->ctx, -7);											// [this][concat][this][Array][push][this][buffer]
				duk_call_method(sender->ctx, 1); duk_pop(sender->ctx);					// [this][concat][this][Array]
				duk_call_method(sender->ctx, 1);										// [this][buffer]
			}
			duk_put_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer);			// [this]
			duk_pop(sender->ctx);														// ...
			skip = 0;
		}
	}
}
int ILibDuktape_Stream_UnshiftSink(struct ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	duk_push_fixed_buffer(sender->ctx, unshiftBytes);									// [buffer]
	memcpy_s(Duktape_GetBuffer(sender->ctx, -1, NULL), unshiftBytes, sender->unshiftReserved, unshiftBytes);
	duk_push_heapptr(sender->ctx, sender->object);										// [buffer][stream]
	duk_push_buffer_object(sender->ctx, -2, 0, unshiftBytes, DUK_BUFOBJ_NODEJS_BUFFER);	// [buffer][stream][buffer]
	duk_put_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer);					// [buffer][stream]
	duk_pop_2(sender->ctx);																// ...

	return(unshiftBytes);
}
duk_ret_t ILibDuktape_Stream_Push(duk_context *ctx)
{
	duk_push_this(ctx);																					// [stream]

	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
	if (buffer != NULL)
	{
		duk_push_boolean(ctx, !ILibDuktape_readableStream_WriteDataEx(RS, 0, buffer, (int)bufferLen));		// [stream][buffer][retVal]
	}
	else
	{
		ILibDuktape_readableStream_WriteEnd(RS);
		duk_push_false(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Stream_EndSink(duk_context *ctx)
{
	duk_push_this(ctx);												// [stream]
	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_readableStream_WriteEnd(RS);
	return(0);
}
duk_ret_t ILibDuktape_Stream_readonlyError(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_size_t len;
	char *propName = Duktape_GetStringPropertyValueEx(ctx, -1, "propName", "<unknown>", &len);
	duk_push_lstring(ctx, propName, len);
	duk_get_prop_string(ctx, -1, "concat");					// [string][concat]
	duk_swap_top(ctx, -2);									// [concat][this]
	duk_push_string(ctx, " is readonly");					// [concat][this][str]
	duk_call_method(ctx, 1);								// [str]
	duk_throw(ctx);
	return(0);
}
duk_idx_t ILibDuktape_Stream_newReadable(duk_context *ctx)
{
	ILibDuktape_readableStream *RS;
	duk_push_object(ctx);							// [Readable]
	ILibDuktape_WriteID(ctx, "stream.readable");
	RS = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_Stream_PauseSink, ILibDuktape_Stream_ResumeSink, ILibDuktape_Stream_UnshiftSink, NULL);
	RS->paused = 1;

	duk_push_pointer(ctx, RS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_CreateInstanceMethod(ctx, "push", ILibDuktape_Stream_Push, DUK_VARARGS);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "end", ILibDuktape_Stream_EndSink);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_read", ILibDuktape_Stream_readonlyError);
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Stream_Writable_WriteSink_Flush(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibTransport_DoneState *retVal = (ILibTransport_DoneState*)Duktape_GetPointerProperty(ctx, -1, "retval");
	if (retVal != NULL)
	{
		*retVal = ILibTransport_DoneState_COMPLETE;
	}
	else
	{
		ILibDuktape_WritableStream *WS = (ILibDuktape_WritableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_WritablePtr);
		ILibDuktape_WritableStream_Ready(WS);
	}
	return(0);
}
ILibTransport_DoneState ILibDuktape_Stream_Writable_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	void *h;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_INCOMPLETE;
	duk_push_this(stream->ctx);																		// [writable]
	int bufmode = Duktape_GetIntPropertyValue(stream->ctx, -1, "bufferMode", 0);
	duk_get_prop_string(stream->ctx, -1, "_write");													// [writable][_write]
	duk_swap_top(stream->ctx, -2);																	// [_write][this]
	if(duk_stream_flags_isBuffer(stream->Reserved))
	{
		if (bufmode == 0)
		{
			// Legacy Mode. We use an external buffer, so a memcpy does not occur. JS must copy memory if it needs to save it
			duk_push_external_buffer(stream->ctx);													// [_write][this][extBuffer]
			duk_config_buffer(stream->ctx, -1, buffer, (duk_size_t)bufferLen);
		}
		else
		{
			// Compliant Mode. We copy the buffer into a buffer that will be wholly owned by the recipient
			char *cb = (char*)duk_push_fixed_buffer(stream->ctx, (duk_size_t)bufferLen);			// [_write][this][extBuffer]
			memcpy_s(cb, (size_t)bufferLen, buffer, (size_t)bufferLen);
		}
		duk_push_buffer_object(stream->ctx, -1, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [_write][this][extBuffer][buffer]
		duk_remove(stream->ctx, -2);																// [_write][this][buffer]	
	}
	else
	{
		duk_push_lstring(stream->ctx, buffer, (duk_size_t)bufferLen);								// [_write][this][string]
	}
	duk_push_c_function(stream->ctx, ILibDuktape_Stream_Writable_WriteSink_Flush, DUK_VARARGS);		// [_write][this][string/buffer][callback]
	h = duk_get_heapptr(stream->ctx, -1);
	duk_push_heap_stash(stream->ctx);																// [_write][this][string/buffer][callback][stash]
	duk_dup(stream->ctx, -2);																		// [_write][this][string/buffer][callback][stash][callback]
	duk_put_prop_string(stream->ctx, -2, Duktape_GetStashKey(h));									// [_write][this][string/buffer][callback][stash]
	duk_pop(stream->ctx);																			// [_write][this][string/buffer][callback]
	duk_push_pointer(stream->ctx, stream); duk_put_prop_string(stream->ctx, -2, ILibDuktape_Stream_WritablePtr);

	duk_push_pointer(stream->ctx, &retVal);															// [_write][this][string/buffer][callback][retval]
	duk_put_prop_string(stream->ctx, -2, "retval");													// [_write][this][string/buffer][callback]
	if (duk_pcall_method(stream->ctx, 2) != 0)
	{
		ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "stream.writable.write(): "); retVal = ILibTransport_DoneState_ERROR;
	}
	else
	{
		if (retVal != ILibTransport_DoneState_COMPLETE)
		{
			retVal = duk_to_boolean(stream->ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
		}
	}
	duk_pop(stream->ctx);																			// ...

	duk_push_heapptr(stream->ctx, h);																// [callback]
	duk_del_prop_string(stream->ctx, -1, "retval");
	duk_pop(stream->ctx);																			// ...
	
	duk_push_heap_stash(stream->ctx);
	duk_del_prop_string(stream->ctx, -1, Duktape_GetStashKey(h));
	duk_pop(stream->ctx);
	return(retVal);
}
duk_ret_t ILibDuktape_Stream_Writable_EndSink_finish(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)Duktape_GetPointerProperty(ctx, -1, "ptr");
	if (ILibMemory_CanaryOK(ws))
	{
		ILibDuktape_WritableStream_Finish(ws);
	}
	return(0);
}
void ILibDuktape_Stream_Writable_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	duk_push_this(stream->ctx);															// [writable]
	duk_get_prop_string(stream->ctx, -1, "_final");										// [writable][_final]
	duk_swap_top(stream->ctx, -2);														// [_final][this]
	duk_push_c_function(stream->ctx, ILibDuktape_Stream_Writable_EndSink_finish, 0);	// [_final][this][callback]
	duk_push_pointer(stream->ctx, stream); duk_put_prop_string(stream->ctx, -2, "ptr");
	if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "stream.writable._final(): "); }
	duk_pop(stream->ctx);								// ...
}
duk_ret_t ILibDuktape_Stream_newWritable(duk_context *ctx)
{
	ILibDuktape_WritableStream *WS;
	duk_push_object(ctx);						// [Writable]
	ILibDuktape_WriteID(ctx, "stream.writable");
	WS = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_Stream_Writable_WriteSink, ILibDuktape_Stream_Writable_EndSink, NULL);
	WS->JSCreated = 1;

	duk_push_pointer(ctx, WS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_WritablePtr);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "write");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_write"); }
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
	}
	return(1);
}
void ILibDuktape_Stream_Duplex_PauseSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_PauseSink(stream->readableStream, user);
}
void ILibDuktape_Stream_Duplex_ResumeSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_ResumeSink(stream->readableStream, user);
}
int ILibDuktape_Stream_Duplex_UnshiftSink(ILibDuktape_DuplexStream *stream, int unshiftBytes, void *user)
{
	return(ILibDuktape_Stream_UnshiftSink(stream->readableStream, unshiftBytes, user));
}
ILibTransport_DoneState ILibDuktape_Stream_Duplex_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	return(ILibDuktape_Stream_Writable_WriteSink(stream->writableStream, buffer, bufferLen, user));
}
void ILibDuktape_Stream_Duplex_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_Writable_EndSink(stream->writableStream, user);
}

duk_ret_t ILibDuktape_Stream_newDuplex(duk_context *ctx)
{
	ILibDuktape_DuplexStream *DS;
	duk_push_object(ctx);						// [Duplex]
	ILibDuktape_WriteID(ctx, "stream.Duplex");
	DS = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_Stream_Duplex_WriteSink, ILibDuktape_Stream_Duplex_EndSink, ILibDuktape_Stream_Duplex_PauseSink, ILibDuktape_Stream_Duplex_ResumeSink, ILibDuktape_Stream_Duplex_UnshiftSink, NULL);
	DS->writableStream->JSCreated = 1;

	duk_push_pointer(ctx, DS->writableStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_WritablePtr);

	duk_push_pointer(ctx, DS->readableStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_CreateInstanceMethod(ctx, "push", ILibDuktape_Stream_Push, DUK_VARARGS);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "end", ILibDuktape_Stream_EndSink);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "write");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_write"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_write", ILibDuktape_Stream_readonlyError);
		}
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_final", ILibDuktape_Stream_readonlyError);
		}
		h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_read", ILibDuktape_Stream_readonlyError);
		}
	}
	return(1);
}
void ILibDuktape_Stream_Init(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);					// [stream
	ILibDuktape_WriteID(ctx, "stream");
	ILibDuktape_CreateInstanceMethod(ctx, "Readable", ILibDuktape_Stream_newReadable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Writable", ILibDuktape_Stream_newWritable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Duplex", ILibDuktape_Stream_newDuplex, DUK_VARARGS);
}
void ILibDuktape_Polyfills_debugGC2(duk_context *ctx, void ** args, int argsLen)
{
	if (duk_ctx_is_alive((duk_context*)args[1]) && duk_ctx_is_valid((uintptr_t)args[2], ctx) && duk_ctx_shutting_down(ctx)==0)
	{
		if (g_displayFinalizerMessages) { printf("=> GC();\n"); }
		duk_gc(ctx, 0);
	}
}
duk_ret_t ILibDuktape_Polyfills_debugGC(duk_context *ctx)
{
	ILibDuktape_Immediate(ctx, (void*[]) { Duktape_GetChain(ctx), ctx, (void*)duk_ctx_nonce(ctx), NULL }, 3, ILibDuktape_Polyfills_debugGC2);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_debug(duk_context *ctx)
{
#ifdef WIN32
	if (IsDebuggerPresent()) { __debugbreak(); }
#elif defined(_POSIX)
	raise(SIGTRAP);
#endif
	return(0);
}
#ifndef MICROSTACK_NOTLS
duk_ret_t ILibDuktape_PKCS7_getSignedDataBlock(duk_context *ctx)
{
	char *hash = ILibMemory_AllocateA(UTIL_SHA256_HASHSIZE);
	char *pkeyHash = ILibMemory_AllocateA(UTIL_SHA256_HASHSIZE);
	unsigned int size, r;
	BIO *out = NULL;
	PKCS7 *message = NULL;
	char* data2 = NULL;
	STACK_OF(X509) *st = NULL;

	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	message = d2i_PKCS7(NULL, (const unsigned char**)&buffer, (long)bufferLen);
	if (message == NULL) { return(ILibDuktape_Error(ctx, "PKCS7 Error")); }

	// Lets rebuild the original message and check the size
	size = i2d_PKCS7(message, NULL);
	if (size < (unsigned int)bufferLen) { PKCS7_free(message); return(ILibDuktape_Error(ctx, "PKCS7 Error")); }

	out = BIO_new(BIO_s_mem());

	// Check the PKCS7 signature, but not the certificate chain.
	r = PKCS7_verify(message, NULL, NULL, NULL, out, PKCS7_NOVERIFY);
	if (r == 0) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Verify Error")); }

	// If data block contains less than 32 bytes, fail.
	size = (unsigned int)BIO_get_mem_data(out, &data2);
	if (size <= ILibMemory_AllocateA_Size(hash)) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Size Mismatch Error")); }


	duk_push_object(ctx);												// [val]
	duk_push_fixed_buffer(ctx, size);									// [val][fbuffer]
	duk_dup(ctx, -1);													// [val][fbuffer][dup]
	duk_put_prop_string(ctx, -3, "\xFF_fixedbuffer");					// [val][fbuffer]
	duk_swap_top(ctx, -2);												// [fbuffer][val]
	duk_push_buffer_object(ctx, -2, 0, size, DUK_BUFOBJ_NODEJS_BUFFER); // [fbuffer][val][buffer]
	ILibDuktape_CreateReadonlyProperty(ctx, "data");					// [fbuffer][val]
	memcpy_s(Duktape_GetBuffer(ctx, -2, NULL), size, data2, size);


	// Get the certificate signer
	st = PKCS7_get0_signers(message, NULL, PKCS7_NOVERIFY);
	
	// Get a full certificate hash of the signer
	X509_digest(sk_X509_value(st, 0), EVP_sha256(), (unsigned char*)hash, NULL);
	X509_pubkey_digest(sk_X509_value(st, 0), EVP_sha256(), (unsigned char*)pkeyHash, NULL); 

	sk_X509_free(st);
	
	// Check certificate hash with first 32 bytes of data.
	if (memcmp(hash, Duktape_GetBuffer(ctx, -2, NULL), ILibMemory_AllocateA_Size(hash)) != 0) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Certificate Hash Mismatch Error")); }
	char *tmp = ILibMemory_AllocateA(1 + (ILibMemory_AllocateA_Size(hash) * 2));
	util_tohex(hash, (int)ILibMemory_AllocateA_Size(hash), tmp);
	duk_push_object(ctx);												// [fbuffer][val][cert]
	ILibDuktape_WriteID(ctx, "certificate");
	duk_push_string(ctx, tmp);											// [fbuffer][val][cert][fingerprint]
	ILibDuktape_CreateReadonlyProperty(ctx, "fingerprint");				// [fbuffer][val][cert]
	util_tohex(pkeyHash, (int)ILibMemory_AllocateA_Size(pkeyHash), tmp);
	duk_push_string(ctx, tmp);											// [fbuffer][val][cert][publickeyhash]
	ILibDuktape_CreateReadonlyProperty(ctx, "publicKeyHash");			// [fbuffer][val][cert]

	ILibDuktape_CreateReadonlyProperty(ctx, "signingCertificate");		// [fbuffer][val]

	// Approved, cleanup and return.
	BIO_free(out);
	PKCS7_free(message);

	return(1);
}
duk_ret_t ILibDuktape_PKCS7_signDataBlockFinalizer(duk_context *ctx)
{
	char *buffer = Duktape_GetPointerProperty(ctx, 0, "\xFF_signature");
	if (buffer != NULL) { free(buffer); }
	return(0);
}
duk_ret_t ILibDuktape_PKCS7_signDataBlock(duk_context *ctx)
{
	duk_get_prop_string(ctx, 1, "secureContext");
	duk_get_prop_string(ctx, -1, "\xFF_SecureContext2CertBuffer");
	struct util_cert *cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	BIO *in = NULL;
	PKCS7 *message = NULL;
	char *signature = NULL;
	int signatureLength = 0;

	// Sign the block
	in = BIO_new_mem_buf(buffer, (int)bufferLen);
	message = PKCS7_sign(cert->x509, cert->pkey, NULL, in, PKCS7_BINARY);
	if (message != NULL)
	{
		signatureLength = i2d_PKCS7(message, (unsigned char**)&signature);
		PKCS7_free(message);
	}
	if (in != NULL) BIO_free(in);
	if (signatureLength <= 0) { return(ILibDuktape_Error(ctx, "PKCS7_signDataBlockError: ")); }

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, signature, signatureLength);
	duk_push_buffer_object(ctx, -1, 0, signatureLength, DUK_BUFOBJ_NODEJS_BUFFER);
	duk_push_pointer(ctx, signature);
	duk_put_prop_string(ctx, -2, "\xFF_signature");
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_PKCS7_signDataBlockFinalizer);

	return(1);
}
void ILibDuktape_PKCS7_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "getSignedDataBlock", ILibDuktape_PKCS7_getSignedDataBlock, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "signDataBlock", ILibDuktape_PKCS7_signDataBlock, DUK_VARARGS);
}

extern uint32_t crc32c(uint32_t crc, const unsigned char* buf, uint32_t len);
extern uint32_t crc32(uint32_t crc, const unsigned char* buf, uint32_t len);
duk_ret_t ILibDuktape_Polyfills_crc32c(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	uint32_t pre = duk_is_number(ctx, 1) ? duk_require_uint(ctx, 1) : 0;
	duk_push_uint(ctx, crc32c(pre, (unsigned char*)buffer, (uint32_t)len));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_crc32(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	uint32_t pre = duk_is_number(ctx, 1) ? duk_require_uint(ctx, 1) : 0;
	duk_push_uint(ctx, crc32(pre, (unsigned char*)buffer, (uint32_t)len));
	return(1);
}
#endif
duk_ret_t ILibDuktape_Polyfills_Object_hashCode(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_push_string(ctx, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_peek(duk_context *ctx)
{
	duk_push_this(ctx);				// [Array]
	duk_get_prop_index(ctx, -1, (duk_uarridx_t)duk_get_length(ctx, -1) - 1);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Object_keys(duk_context *ctx)
{
	duk_push_this(ctx);														// [obj]
	duk_push_array(ctx);													// [obj][keys]
	duk_enum(ctx, -2, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [obj][keys][enum]
	while (duk_next(ctx, -1, 0))											// [obj][keys][enum][key]
	{
		duk_array_push(ctx, -3);											// [obj][keys][enum]
	}
	duk_pop(ctx);															// [obj][keys]
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_function_getter(duk_context *ctx)
{
	duk_push_this(ctx);			// [Function]
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_InfrastructureEvent);
	return(1);
}
void ILibDuktape_Polyfills_function(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Function");										// [g][Function]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Function][prototype]
	ILibDuktape_CreateEventWithGetter(ctx, "internal", ILibDuktape_Polyfills_function_getter);
	duk_pop_2(ctx);																	// [g]
}
void ILibDuktape_Polyfills_object(duk_context *ctx)
{
	// Polyfill Object._hashCode() 
	duk_get_prop_string(ctx, -1, "Object");											// [g][Object]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_hashCode, 0);				// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "_hashCode");							// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_keys, 0);					// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "keys");								// [g][Object][prototype]
	duk_pop_2(ctx);																	// [g]

	duk_get_prop_string(ctx, -1, "Array");											// [g][Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Array][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Array_peek, 0);					// [g][Array][prototype][peek]
	ILibDuktape_CreateReadonlyProperty(ctx, "peek");								// [g][Array][prototype]
	duk_pop_2(ctx);																	// [g]
}


#ifndef MICROSTACK_NOTLS
void ILibDuktape_bignum_addBigNumMethods(duk_context *ctx, BIGNUM *b);
duk_ret_t ILibDuktape_bignum_toString(duk_context *ctx)
{
	duk_push_this(ctx);
	BIGNUM *b = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	if (b != NULL)
	{
		char *numstr = BN_bn2dec(b);
		duk_push_string(ctx, numstr);
		OPENSSL_free(numstr);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid BIGNUM"));
	}
}
duk_ret_t ILibDuktape_bignum_add(duk_context* ctx)
{
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");

	BN_add(ret, r1, r2);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_sub(duk_context* ctx)
{
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");

	BN_sub(ret, r1, r2);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_mul(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_mul(ret, r1, r2, bx);
	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_div(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_div(ret, NULL, r1, r2, bx);

	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_mod(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_div(NULL, ret, r1, r2, bx);

	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_cmp(duk_context *ctx)
{
	BIGNUM *r1, *r2;
	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	duk_push_int(ctx, BN_cmp(r2, r1));
	return(1);
}

duk_ret_t ILibDuktape_bignum_finalizer(duk_context *ctx)
{
	BIGNUM *b = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	if (b != NULL)
	{
		BN_free(b);
	}
	return(0);
}
void ILibDuktape_bignum_addBigNumMethods(duk_context *ctx, BIGNUM *b)
{
	duk_push_object(ctx);
	duk_push_pointer(ctx, b); duk_put_prop_string(ctx, -2, "\xFF_BIGNUM");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "toString", ILibDuktape_bignum_toString, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "add", ILibDuktape_bignum_add, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "sub", ILibDuktape_bignum_sub, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "mul", ILibDuktape_bignum_mul, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "div", ILibDuktape_bignum_div, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "mod", ILibDuktape_bignum_mod, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "cmp", ILibDuktape_bignum_cmp, 1);

	duk_push_c_function(ctx, ILibDuktape_bignum_finalizer, 1); duk_set_finalizer(ctx, -2);
	duk_eval_string(ctx, "(function toNumber(){return(parseInt(this.toString()));})"); duk_put_prop_string(ctx, -2, "toNumber");
}
duk_ret_t ILibDuktape_bignum_random(duk_context *ctx)
{
	BIGNUM *r = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BIGNUM *rnd = BN_new();

	if (BN_rand_range(rnd, r) == 0) { return(ILibDuktape_Error(ctx, "Error Generating Random Number")); }
	ILibDuktape_bignum_addBigNumMethods(ctx, rnd);
	return(1);
}
duk_ret_t ILibDuktape_bignum_fromBuffer(duk_context *ctx)
{
	char *endian = duk_get_top(ctx) > 1 ? Duktape_GetStringPropertyValue(ctx, 1, "endian", "big") : "big";
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	BIGNUM *b;

	if (strcmp(endian, "big") == 0)
	{
		b = BN_bin2bn((unsigned char*)buffer, (int)len, NULL);
	}
	else if (strcmp(endian, "little") == 0)
	{
#ifdef OLDSSL
		return(ILibDuktape_Error(ctx, "Invalid endian specified"));
#endif
		b = BN_lebin2bn((unsigned char*)buffer, (int)len, NULL);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid endian specified"));
	}

	ILibDuktape_bignum_addBigNumMethods(ctx, b);
	return(1);
}

duk_ret_t ILibDuktape_bignum_func(duk_context *ctx)
{	
	BIGNUM *b = NULL;
	BN_dec2bn(&b, duk_require_string(ctx, 0));
	ILibDuktape_bignum_addBigNumMethods(ctx, b);
	return(1);
}
void ILibDuktape_bignum_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_bignum_func, DUK_VARARGS);
	duk_push_c_function(ctx, ILibDuktape_bignum_fromBuffer, DUK_VARARGS); duk_put_prop_string(ctx, -2, "fromBuffer");
	duk_push_c_function(ctx, ILibDuktape_bignum_random, DUK_VARARGS); duk_put_prop_string(ctx, -2, "random");
	
	char randRange[] = "exports.randomRange = function randomRange(low, high)\
						{\
							var result = exports.random(high.sub(low)).add(low);\
							return(result);\
						};";
	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, randRange, sizeof(randRange) - 1);
}
void ILibDuktape_dataGenerator_onPause(struct ILibDuktape_readableStream *sender, void *user)
{

}
void ILibDuktape_dataGenerator_onResume(struct ILibDuktape_readableStream *sender, void *user)
{
	SHA256_CTX shctx;

	char *buffer = (char*)user;
	size_t bufferLen = ILibMemory_Size(buffer);
	int val;

	while (sender->paused == 0)
	{
		duk_push_heapptr(sender->ctx, sender->object);
		val = Duktape_GetIntPropertyValue(sender->ctx, -1, "\xFF_counter", 0);
		duk_push_int(sender->ctx, (val + 1) < 255 ? (val+1) : 0); duk_put_prop_string(sender->ctx, -2, "\xFF_counter");
		duk_pop(sender->ctx);

		//util_random((int)(bufferLen - UTIL_SHA256_HASHSIZE), buffer + UTIL_SHA256_HASHSIZE);
		memset(buffer + UTIL_SHA256_HASHSIZE, val, bufferLen - UTIL_SHA256_HASHSIZE);


		SHA256_Init(&shctx);
		SHA256_Update(&shctx, buffer + UTIL_SHA256_HASHSIZE, bufferLen - UTIL_SHA256_HASHSIZE);
		SHA256_Final((unsigned char*)buffer, &shctx);
		ILibDuktape_readableStream_WriteData(sender, buffer, (int)bufferLen);
	}
}
duk_ret_t ILibDuktape_dataGenerator_const(duk_context *ctx)
{
	int bufSize = (int)duk_require_int(ctx, 0);
	void *buffer;

	if (bufSize <= UTIL_SHA256_HASHSIZE)
	{
		return(ILibDuktape_Error(ctx, "Value too small. Must be > %d", UTIL_SHA256_HASHSIZE));
	}

	duk_push_object(ctx);
	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, "\xFF_counter");
	buffer = Duktape_PushBuffer(ctx, bufSize);
	duk_put_prop_string(ctx, -2, "\xFF_buffer");
	ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_dataGenerator_onPause, ILibDuktape_dataGenerator_onResume, buffer)->paused = 1;
	return(1);
}
void ILibDuktape_dataGenerator_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_dataGenerator_const, DUK_VARARGS);
}
#endif

void ILibDuktape_Polyfills_JS_Init(duk_context *ctx)
{
	// {{ BEGIN AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvftX8EYK9SpGk5O9aZFNA2wWXacf6WldGIo0sumlSZWknBiB//sOqQ9Tsp20q4MNkTNvZvjejDjYJJoUWq25AXJJNPwouQZG6yUaTQbOQqoMeBYazJMFSDvF9duMRqy240X6KbFLNESAFIyJC5HYXOk1ubwk9JHL87eUvCeMzvCJZ7OCFzCbUfKmCfGG0N8+XN1+uqYRGRPWwKSPGYvc5lm9ORkM8lKmlitJssQmfyYyE6BZuizlv9HgeUDwcSkJkBP/wnNS7ca4tMAkfycXEXkmdslNXEqz5Lmt3SdYpy21nJBd68rQC+uqEDQk2bdbac/ffrxhoygi70gI/ROwbX4u+RbXCJ4Cuxi6rLHai2jS2hXJVqjEcSBLIap1q7f+v6rWPXurv77eTeMi0QaYCxFb9dVqLhcsqkGr0tLEpkvCIOoB+fRrFcRzDStGb+UmEUjRFzCFkqiXL5AC30BGa0T31BUGEQ6TPDvroxtWJ44na0ph33dfxzQM8Zrz0Fscq/IprLJHrTttlMTrNDYkoQea4Wki0m4vxh8l6O2Vaw6mHlZDbATY4C92RahKPCbHJDw2zcdaAIZVDNFg1YZ3NfreM5N2YeUXVhi8LhQR4zlGxPVnkq6zMaE+FTrEgKKEMXGbu30vuMRcVzo59dl3YKngWETY8xIsjeIUxW/hWkkJPmH27Ksb+98GEHu8mQX1xq4rkho+Rn+aVliY6f4QotZ4n1VLvnNyokaPoPeDAB1LkNkJ6EP4E9JPhTJdnXsFuSkULjhmHQF/lHkOOs4Rg/k+NL71eL5lDU1RD8u5PpT53jkRQqVeZatGjl0PtI4fNbfQDqLG0Gl5SEY9+1WcqmLL0G3YDpZOyR7M7Qebu04bgTDwklKcpI6yrGGtNnAlxEduLEjQpibwuCiOmTsWT0voRTX0bE/r4YjUXtNBRwP/k/9f4/5XeD/FeXAifdZ3g55BeDuw7azBIe8mlUWvXfApNjbRljWTDhvbKAGxUAtGP7tphKdA/gazJH5COnMLcRw3J7oQ6iER8dytl8birYEYsPd8Daq0rE/Znq5OoG8yeRBArHLLNkltEDGI5Z7mejGHJ25ZcwJDcj4ajRpig4HeTCrMAQehXYLsj+29QT9FN3L9HK8nLk7paqzTf6Z39+T6bjq9ub6/+fCdNreOg8KCg6vjQIZl4qRH5hHs4DNMWJh8BibVvLBKG9rJtKn7oKTNSwWFqW2C0J2UD68G3ZwsUoutkaufzcidWy/yETNn1efWmfl7wOt2XtNrlZUYBJ4Kpa3xn1Wv7nH1N6yEMQ70gV/X/wBv5FS0', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('eJztPWtTG0mS3/kVZWJ3JcZCYO/cXAQcs4cB73LrBQLwehzGRzStEuqh1a3tB6Dwcr/9MrMeXVVd3WoJvLcXd4oZ21LXIysr35lVvfXD2kE6m2fR7aRgb7ffbrPjpOAxO0izWZoFRZQma/8elMUkzdi7bB4k7Dzla2sfopAnOR+xMhnxjBUTzvZnQQh/yScD9lee5dCbvR1usz42WJeP1jd21+ZpyabBnCVpwcqcwwBRzsZRzBl/DPmsYFHCwnQ6i6MgCTl7iIoJTSKHGK59lgOkN0UAbQNoPYNvY7MVC4q1NQafSVHMdra2Hh4ehgFBOUyz261YtMq3PhwfHJ1cHG0CpGtrH5OY5znL+N/KKIMF3sxZMAM4wuAGoIuDBwaYCG4zDs+KFOF8yKIiSm4HLE/HxUOQ8bVRlBdZdFMWFoIUVLBSswGgCLC6vn/Bji/W2bv9i+OLwdqn48s/nX68ZJ/2z8/3Ty6Pjy7Y6Tk7OD05PL48Pj2Bb+/Z/sln9ufjk8MB44AemIQ/zjKEHQCMEHV8NFy74NyafJwKYPIZD6NxFMKKktsyuOXsNr3nWQILYTOeTaMcNy8H0EZrcTSNCiKFvL6c4doPW2tra1tb8B+7xG2E/wI24TEMw8oiiqNiDh2CAh+UuUApDvAXnk/Y/i1PCoHIvAjimEVFzuMxDhbgODdBeHebpTAty3l2D3MOCGPQchYHBSxnmovRcciARsvLGdBukQ8RqrUim699IzJQAAJgKfwPYBGoszSeA+nFhBvYiv0sC+YDhGnMi3BioguA5zGf4iTRGEAFlMNO5gMgl2l6j7ijxmVGEOP3v5VpwXNsDU+AlDLaDqARBOj05lceFsMRH0cJP5NA9Wn+4SxLi7SYz2C9vVtenAVZMOUFz44eewPqjJ9v+l/4uQ/iku+wcZmEuFmsn0CXAYPhgzIu/opPN6wOdncxBNAOLqfYrT1D9PQjtse2d1nE/o14dhjz5LaY7LLXr6ONWo/6+PgBXPSx75fo6xD2HDbqE9AvActes95eb6M+UvNo+AFwASw9ZnmD3JXc0pASQhj5zUZ9TSZMMIoJT28dAGHf5OD0UA/8hlCkht7EodlTG3hlltAEDSDU+9Z/UaNY22kPV3V6gic2zb8wybOVCfh7kq/CEZGmzTX93uZmD6jAM2grFp/WwgBQ0n/cWPsGjzzSZGnMRiBDH5WuqqF5YOF5ZTQf4yTL4bqTcPiHywVj31YXD0QV0Qtw36YrRb4TtZBC4S9OISMYouAr8mIn+pCCeFijRTFEfQeicT/6eW+7K5XQ4DkaZLwPmson1J/+ERtkcTShi33+jEwNrZTA/OUXtA+xAdopYKNsbv7yy97nzy/E4iS9um9h1GX/mlSp+oVk1+m4j3z42of876JJmzVo6+5qk1QjAdAqTMY8BXECnkB4l6M9iXs0U3hlAFsZwoycdnoa3JFNJ7hxGiXRtJyCNVrgbqOfkBm8mZOJh3Y4fFnT89JMeuPyPsw1zTck6SHep2AL77Hrv1z8qS9XiIikZhYr9YGF8zCLZjhsb8CSMo432N4e/YP97nc40NBowl7tyTbfmBhtVuYkVI1Ge+soYd2eIGxh49R2NIITATMG8xP43ghO1aQFnKqRAY7Rsxs46DQGSSs4RpNmcIxGFThmzwocDQ82QR/WGnnN5jVFkWGagLtV5ERTm5u6W0WE0j6QfhHPhNSh1sBasOq9X0C+SMFiuqvST9qcBgn4Q9nw11zPriR0HXNCRPcUHD2DzWoC2pYcYiy/RK6408auXIBGrF6+xOqa6Ny601NwHy/EUn277SIeVoEzOb3sbaovTm1XMBrljjKWaJYGJezNDcddzcvpwm2oI8QBq8KMC6+JIBvDPM558youCtRiCUgzZ0C9oOFwyD7wogeLjfNUSCxNfXq5OTRz1EzGiukMiSpL4TmsSfrluBO9hyj5/dse+wPrVe5+j+0w2j5y13u2QEeNbH6vqykxm6T4fu+aRjlJR/x41NsY5tXa+o26Aj9SUzy2aUVJggYeL4EGpPOAFoK1KrQRPoGCTB/yAQZOzEXSQw4sPwdNmtzSbrmoBBLFtQFJ9lfF5cYiHd+B7BAGl8xs9D1J/jQ0bCTYA2DI5mA1RWD94Iol/ejIiJir0ovyuYShT9JP60WFhLwYpWUxxDgb7Ddg7bgaVY6oYEUGTGMOZso4fdPv9ZQbTFRKQocJht91fn4UUjHwi0XRpmdoZtXrZ3B7PDJeMJI04kFlMD694aMR8tEsCDEglDA1Kga6KIIVguk4xQBeORP2yekFr4SGBt8DJlmCCiZj22RTKZzlc1tE62HFP6ht0e8xYKVfYRsFDisKVStXFtserh+0p41cTSEay7CXj/P3GOCtBAV/5OFZAF5iJeebyd5FsjOg+LeCHofWCxjSY3MZpoypScr90UiEo7UqxsiuEV4kmhVRaRCpIPX13uowtZQC7GNOwdKgMASpyQcOZwYGa+oO7+Y4imBNLfQAJ5sZv8UwMqxsWEIL1EOXKbb9M5/3dUt8tJlzEc6Fpkg2AsunDwnPSE5qtEejjSG5aS16RshN/hj6dKbad/xTKySLM04T9iFKSqBCYcs467T8r1k6K4ESTMx+PD5UllFZITdvEjRqYiTB0tQaLloK8LaM5VL7aERBjQ5kI5q24fxjNOqXbfhsxmYH4kDaABhMztfs8RpYSLKAtquUx/uJ9zKM/BPaQOdnHLBNCDw9E3mGlPxSfDhBjQZ/1+2aoTuO2jcK05NrJTY1AsH3wFHODWD3oLGCg3xVKQUfODpQQY6ZAlAjqWsFU0etg2VPldZIEzUMuGFJrzDMGy2K0plIZew1bCYywI5PyvpszpUV9cCaU4jPHfn33h5K0T90sQK8Y++IYewp5L6hwN2piWCnKfrul/MZoKG3//Hy9Pricv/8sjeoyyvyZhWy7OfXes9gWVlZ8eKTIEO5DZaP51Vuro+pOop4kurhRLbsThvOlIaX2zSl5WWbU6Jo9KSlem2gGIMpi2SRugOdqmY13U5o0DN94Ns4vQni4e2pJOoGtxNMSxFLinL62+1HHli+0eQGpWYrgMHb2yfcYF637U2UBGAjLnC81IwG1XrmFWO5Ez9p+XY8ZgETwk9klx8ClBWwbQOQMz1MNyZhXI44RuNkqC4GpYoqRqxV+XUzdPkeJjxxNQ2xnN4OrQLGKPdFfO9inoR9LY836lvD+g5+q6CEi/gvX83wmPVUKIdvYKuUWch3Kg0AjjF/OCGhpjpIa+211gwUPaswqPAHsFEsZDbfBGe0h4pWC1TEoDCB0ORH7YEZeETJEINZYImPo9tSlBAI5BPiFZrDMsvQmnpIszsS6IC2sEilijVSDYifflTxqY5AVoDtrb+hEKPPGJfBNcf09EvUvisW/fYkogJm26m3J4zS492X2F+EHfZO29Z+gRGjOdXD6JamPkdHA+hKW8NAUoGhfO9TuKSXz/OCT8F7BhzYJCIRsN5bV6vf7OHK7Va73ShSboNBj9XiFOI0IZqjVarGE2d6Mqhkr04j13EaBsrBlISio1mWZaorEBIsLTCMx05gmA3lSMfJGY6DvhXov11HNjk2k+CrOciYAF3nWJVZyJKGSVrGIxRFlSOBxpGrB64lO82QGF9Vcc+Gx71e28OtmtPlpvo8mPEm/mzZbnJE1bOe9pNLRcaqZf3qkQ3fKkxf3/zcgKF71x7dEIC24XWR6jKQ4tjttCJy6HzD+12vJ1sYeibxxC2M+Zrko0OzUtEuGF7EG6IupD8OwA1cmqUNBW5aP6i+LQVksRAFW0iRS69B53FWwZ2ZSViAO9tAWxl3XXDSYvMZrKwNpCSleVHnCClkKp1qPq15aA7l53oiWgGgE7Z3roWlz9nuoIacuJ+EyPZfPbE/9uXw9OTo61Xi5CcWxo3qXCpCETpc65AST6jcj+JAKtAvTMGsTMSzcZZO2UUw5n9JRxxF1gkvJBtbE1kxm5sQY9RidNXXQcLQyZOb7C9iBXnEPdEwL7qOzs9Pz78yFDXYq45fMFGLvqVJ0ejI70MzntHFnHDBVxw8DcLTC1D0fIT59A9BmYQTXfSHVYIitkPxzjKHQaX/nsgCS8C3QDU2k7YjRX5kfGWgjdU8lcEFzM2WMwZWR87je2HEB6EoJ80nNPyw3QcbBRnsVk39AVqGcRqM+osJlbHNnxEOrAzFeG5MCxfafDgcdotGdmckA6/9mrbzF1IklkdAWSxvOytugBgIZrMPYFNhv/5GQ58uAYRqAtpIbJ7vsC+9D+ltlAjG7H31dzFjD196m3f30ze9r7WWpilJvbrLFCc8xyqew8+3TsM28p7rpb4380aOIApGI6woOT55d/rx5JB9PDwDjohFHe8nfnN+ecAOgyKQ5LxMAB35HGxj4PPapnaj7k+i7hl8u4w/oC5AwEQoDtdci5lIQSGp34KDlrTHFlh4h1VEZ6c+vMTGZRaMx1HooTXhYUInIMoouUFn1NPqLEtvgbh2EDfep0UapjEMAVvh746+Dzw/K29Ahw/gl+g+KMDrOUynAQiVep/DKjy0I0OGB5hIC2JZHi2Xdvb2rGV5R6NbDk/vgSmC+CyFuecwGuwLsJGnNamgkROaw89TtfuW6lLbDMIHiPK9/HYOO9fH7Vted1cMIGwLGUYg2WHaFSoszH4tcyORstYyFdHnBQ5k5AgNsVu3cJAHaOYO1P/l9M/WMvBPGcVfUjH7kFFZJbhm6fjxRzQIowIsrzBOc27hR+oCEZ6CPliBNEoTIDlEFg9GolApniMyZLHTH4PsBqv+D1LAJXGFznKpYWXoP8oxjg5WD8eFBFkEMABv3Mkd6BDHRNwS1H2sl2EyvCTrOnJ+DDrLG4O9vs7votkRWCi9ARjfGyLZ2IBg25BRmWk8sQFEA1iYoV9fJkb0Lqino/VzKat+72SktT0zCRxrZqCpVBkueqyVTI02wv5ormIlw4JkP3UU4YWutp5pZnRMkFjFCbY+NiAYlolrWFkCiMKp0CZK7iicanZFq84tC3yOql9R0ftGtUuY0A8zfLVXOlhFIegcCD4v0lmvFiHG8p2IEs4Vb7ukPMv4fZSWeeWacePEjLSLwzQBgVjK81SynTjjpebyF2SYks6f1v0kQKvCWbAShgddqNZVAp4mBF7BxdkYk0m8jmQbb18gS79FplbySo8lVtTI1G/lqgYYkDRrMHMOCAJ+nCumMGIXRkAa/zkCm+u9CNK59SRgSZ1lfBw91p5oQJTj7jYwapea8lIvmIHcxX3D2Ksp9EU1m8ixysztfYS1DTLhSkeZ8NSeDsNoxXVelaxTBoBi/tBaFcNiM9Tx35rZGjcEVYTkRPhKAQsn9uUGeYWeeEe5oEPKvTUFbAShUtICuzDK1JFWFCUFIrzBRFppIE5tRbm0NSn6pPAxZOagVAJFw05g+zFJRDQvLRoPiZNpj2pUpEcekFMUl2CEQaFf51DJB67KxezCHicM7aGzb7RegRyBKGH5KWvvyZVTIJ9q4mlz81qkNtHjkKH0OoIrXIyDEE//YSFAGPMgQZ9c4FmkO4I8T8PIru+o0mn4sdjMww94rEfFTg+jTNWAVqgwmbGpv25jd5eyu7MiVhLYkqutNmc9qiYJpl0qdlDVrsjrG5JlUKOPVcNuHeq17AXLRTv+Lqkm47yLqCH87kG4UZT7onAGpix17uyadlcUZVNcKqnpXgtdBjkDf2m6W9LeINI7VJJL6Coc2bH+GvfolWeP6pPLpYI3cpImm8oj0Wdua4EKhYdKdYDwlsav+SHTk9/z+CNW8VYYUanWLXcN+JEdhrN05pqIxmMYTzUUucotK9CgPk6NKPxygLCTGphxmbDe+9kHR70r/jhilMsxdtdXPtvYH7aE+leyCpOhPyw1wOH+8dnBMhB70dww+ijKnrtCPYTaKtXfSx/hJIqtgjr64VpSMhVW8BBTybDFoKu38gmI7i89+OurDyTsrJgoBbLAZUCH6mRUiEaGDXk4LNILcURpA02StnF5ln2XcaNE8XwDidkCuaW/opCrxM8RtR7rcc7+zoKHO5il2xTfOoLCKE75m232X2zrP2tkf3U13NroPtISk8Inn+zlM0B9Me6vA0aurtZ/m8Mf6wP2m+2N3eWGooqJPpqr3fs9dWu6/tS7Sta77RNSxtYSZNDEyqsMYbJy5/7oylFj2aShz0MQFUfC66u1so9xWMde8NOkxpoi7PkseBAXiEynWOJKasvQaEtrsKurF1Rh/sGWE5LajU7uv6Dmhx3sfRXcJuj492+vrsLpiKqcUJBuHaBn5CMUAMejqaj2qJG2nKeWBniGvH6GSG7uatCdQ3PPCy8ZQWIdYHpOkPiATmdhqkUHLQzXqe5qtJmSNBYlcurDOTYlBSmWzgybYQ3Y9cMouE3SvIhCd2iZjmpKRuU6irwQc+8xW+bsRCMOWN2Za0dDLVBU1XeZ6Le3AD/PdN2asbcSUdZJsg7xKjHP+riLSf3EmxsCS8HGtSfeQDW+zn6Zdb6GZ3lwfnrCfk1vxNG0oitl6Mt93FnI+yyC/I7l4YSPyhj2r84w1mlFbL2pW6MbShGV5l3eApckSkdRSOksi56H1zJYo2Ib5jNYb9Kv5N6y++shGvzUEyR0H8O1FSemDTSF7ksQ13KzL4pYNyZ67CDz+ygzske1QHNzjLmeN3rHgegoxqfbDsx0kXHxjpyGqKvhFPGqRTrfO6ZsFP58kjmHIA7FYaAHdUtXFR3WAdAI7LKbIBfXoVEcsFIB+qYcI6JSXZnQULyw5GlCMRYeuK6uptimBEF1NcWPG7pKeQF16dFqHRRynIx3OrN2XkaPJ1Fyh/WMU7qc70ZHhvUCce1Rfi7jxeqag7//nVkP+rUobXvWPJ3NcDi7XEN19dSY7O0tCPmJ3Dravc1Sqd6rTUBcXJ6enR25Ct6cr2YpNHH+W0uGiJyQY/v5RdlyEDeJtBeA1wV3Aws7gRvPQH5EOW/REp0uD+iWuW7GiM6Zy6tS8BJAEeTGjG/jcViFGH9ieGkfsKLBtoGWp7f25KLfNvJIjKWrKBo1mQ8Apc72qySFFjVGssK0mvIUHLUiZ6NUlGbyxyILFH5QBmmWkCMd0VmnPlZNsS7H+KWNvkO1Ymj4g6g08LtcLVvNw9dq1QzPO4VqbvopLfV9BQwL8Zd0nupVcE0ZIfZl+7dfW61Ep94K1LVZb5Xv55gs/YaAVbVqLEnPeV7GhcjsDcRNRUGsvhbRlAP4O+zNv2xvb1s+8Ix8ZRoNQwe2v7yU7XaVPQctSAqCEHoeY66CFMeyoMxask0yLa0BwfRSJEFp3HL8NO2GcCjsArihUZvYCPo4SjDLt7JV/jzkdrTo+883pv229JFzNcjmGIwVjymNP2tfvP9rniYiXm5WatAtJsAw/3FxejKkIjKzoWEBGvVlNbP3nmc3IE5bastU6D7nxSEHZywRJqb62fgtHx4eX+y/+3B0KMoqjt8zOby87peqLdXdnRvV2ckk3QTjT40Yp7ftqDYgOk7G6QeMpfXf+Ob0nNPMJ+kDwzSEiMGxN3TbCJbcG5OaF8TIeqTdWgWSVcMzCeKCBWO8s8oqSjI0O8GgTrih/QIKxhwv45tV3rDKfofpyLj7WddCDIUZ7b9TjYA9E9e8+W95kzcLGEXk1TUliS69+e6VNxcLKm9aCm6UF1FFAQM/4/tcp67BQRAaVmSwcYJ183rO9eeHC53zLx0Cg27ZFTSXwfgFW4Th7B066OjG5TsYZOaM+t+2/1j9bHiRu2Y02WK3qpKFbvSg9X7Sv4nj0X2zitLqrSfbs2L0ZiLJiaC2h+qAwE7Shm23LUVZw0H12ZjgWTbaZzatH0jyG5ikX1o0i46xCI5CTcHExtiq5rimaAZMHZ9bVuUY4x09CnlkDLY0uKIA2wuuZ3gJKx0QdG+DAGp1Dw3u6Z67RlyiRXBWN98ZgrNFDldCVXCvXepo1FL+k8jcZnnbKA9eWfJAroMuHa/donVt3BVJjOWo/f4GTmHobwuEAUvx1vgHcOfp4lG6c5ba4uX6QpsXWq3/z5o/KxowToDs/4Rqa1Br+rn/SHuDWtit4di4BK/h0ZlauByOiVN+DSfTm1NxL6xIOtSpL6FZ6s6J5d6Iu4XNdZi8rm/22COzohZJNRWwpwx5V2ao7FpeYG9V5CtSSBNer9onh3Tg1CljS1Gd3ElBkkjvhncVMGkK+LAbncBo2R68W2yaYm4LMEcv4ZDXbFUos7TYjv114GtltbFbaD9xx/4qkLNL7yVhH/htEM71oao/iTeTKK1KV7fKa6EpkRiPN8vZKCiMY0H5PL8Wv/WjXLs0Nz/9uOFcHi42VmnMnugz6skkspBxWu+pfW44BaDTH3tsfb16Ons0LpDS0PgOdyINQGcAU586+YNpvrwrx2MQT0iBfWg0YD3MwPz0I96GV9WogRq179BQ9/EuugbDETUGDlG8aMhRsg5I4hBowkQDN5HmoIxLrR6MDgLMZEn31HuNcXDHP9Jk9kkAP6QeaM9Vyne9Gmq9Mnx8UXyCRRbkzx7rN9ObF4wYotGUklJEMYYFyWYbs5HQjCJFNAnu8WpyPBEaYUK6enOPtV2vGm8mjPLzNC36jRd/iTzeKMUjgDQZT9LydmK+IogECN7EZMsnEXKIozsez9k4iGJxJa6Q8HgxH6az3RtwDT4iZ6IQagOXFqfpjIzzGx4G+Moo4qkQRNIwVKck0WYKMXBA0k4WjoccwIlSL22i4dX7AUWYD4fiUitT1pWSpvyFF9fcUzlkqhebDAxeN0xgg1f7NfJ+2VyteYPV8va0XkdzuQvSHoof48KrYpKlD6zfi0ko92q3/VdCcaUao/prKurSVB0Hbggm1OiDEfsbB4mFgWTO2FJZM25hLcHKdKemSvqi+UP3pnEGdk3NWTG0MPKUNSDdbUklgY3XmAn6tW8zoy+7tZG6lxfCnAP2JcXCu6oAUsRTQLBvIti1Oj+rxg9kvrzXsGPpn3gHCPR6vcfMgup6PXV7VZ9TWIrk6gI2hKGn8po0uizLoWffQgymccm7bQq6j2uRnmoZQKMfrF8Vb/oZ1NDyUOLHvYfdDw5+VmXZhmX43+6zEhurTxd2boKmPmIdV4rVx3XY/SizAfrBlSfiuoyj878eHxyxk9NLRqlS9oPP7GgaronKlhy6VbfVsbF0Xv4FMdEKav3yem1Ev1KuLmY1svugdnmq+5yIrziW3/qVZTtgP23DZ8AcL2HXnbKyfvFeLjpmXHeaLaNPoIkMQ9b/cPTH/YPPG762K57Kq7PXc3RIp7qSLlOasfTaUx1S/1f/QT2qkHImeVWfpQkli19EYR9jRhMY9aG67tW+X9ldbmsZipQn4cI3blncc5XsJ4xnGea1w7DM6MJarLIrlcATbmgb7yxiHZsm6VJcUQorjH5MNJ/IQIK4x0Vdma9AZVPTtXHhp8aCwMTrX8HoxTHPYg6uKaYJjVGHi9MHa2Z8RNWgNaXhK/TqjZWjGnqMJ+UUzwhyeYk+z+tVbdiriaroBk1R74EpSKulf48VR3+ZfR3OZCTKJaaOakch6Q5cs2pM6974+qY7G4+f/3WscVC5h3hJMdaeAlVdZnPBFfgGYfjvp21Z4Z17q/QkFTVW6rmengdxFlB+am+7tsgFpXZhEX4a1aCu49CZqP2E0go6NCYjZSpCBqR6geGwj1K50Q03WEQg3vUiIM8wEZFbF24Qd0qVmMnXQPfFVyFwq6yaeCXcdlWxUTUzrWzz1/rrQ4yLC8nq2W26xrK7T1NNCK5N9WW1rDJ6QRIbElfaHzIvj3qsiyHx1rttu/F3dp3qLpPcnHbfyAN8tbON6aBMvdFG5KncGZyEfJSfBCf0EsDqdYLb1ctmTJyJNwU+iQiwE/qVZYFZrSasImHYzGtqo5r0sW6kmGRle1UjniTP6qVZbtHfswv+6kJ0teq/xZV/i3JpV1nbmusVffbMTZV8Hl28WhVeNd1itb/KApsuxpDUYgoxx0RRZGsUvMpOr/Z8r3BQlD1z6urcvAa+Z0waKQizwhA7byx6lQklm/gxNKWJfwHR++sR/4mJnjJfxwWnio7tF2SFFkw8nxVIdlegv379giTeAriHxP3DnMsqVABQxFQcgOkAsX0Dgdds1/aJh7TVlbqBDam4NMYmYWhaI2BFg3X5Tpdjd0dkdWvpAjvUurSUgm7qbs+XvrC0xh6+pv9/e+lqt5fuj0Ze9ljAIC5dewl7IIpQRA5aHL2Kx8LoxlSyFfshlDqiWjwXHfoNKWldZ9BLY5WQHlhvbXGz1ZVNjS3ognhhH8JXUfGw7rvNbYGvt3xYCTWluoPEmFs6go/mFSsijHCVHFEQRIc9qkj3kN7S5Ophz+igjRudhGuE/Z6Ll3T5pq/mozILiVc7jmHtibp6Io4S3hnERfA1v8ymEdXg66zSCVQXeTTrhqIPstvcIBr8KuBunMAa2Zxtwx2it3nz04/Yv1d7ZNY0EK7kLRoZsqdR16BLHTRerfS/QiHVfy0PMVWLeYsaEFJR1KDvjVl9HxvnHxBGKv+n7tcrAWT490N2QVl0TM5nnK6ju6Gr9vEC8vk0xas8b0p62WJOLxOmOwtxMDn8RTnDih+n/kcChjFzHSff9bdRsQKsp/aEEEB6LoxuC9nnjG4JSKX8zd92hbx8rlT2TW3aGD67o2HqZhfVM4lh6MgpjF/URTv+SbCYtMsUljug1mH+1rIOUclpKU4gzP8GjquZPA==', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('eJzVGmtz4kbyO7+iw4dIZLHAXleqDse5cjCb5eJgF+DbSxmXS0gDyBaSTjMy63P836979ECPEdhbm7o9fbAR09PT7+7ppvNDo+8HT6GzXAk46h51YegJ5kLfDwM/NIXje43GhWMxjzMbIs9mIYgVg7PAtPBfstKGf7KQIywcGV3QCaCZLDVbJ40nP4K1+QSeLyDiDBE4HBaOy4B9tlggwPHA8teB65iexWDjiJU8JEFhNP5IEPhzYSKsidABvi3yUGCKRgPwWQkR9DqdzWZjmJJKww+XHTeG4p2LYX8wmgwOkNJG49pzGecQsn9HTogMzp/ADJAOy5wjda65AT8EcxkyXBM+0bkJHeF4yzZwfyE2ZsgatsNF6MwjURBQShVymgdAEZkeNM8mMJw04ZezyXDSbnwaTj9eXk/h09l4fDaaDgcTuBxD/3J0PpwOL0f49gHORn/Ab8PReRsYigcPYZ+DkGhHAh0SHbONxoSxwuELPyaGB8xyFo6FHHnLyFwyWPqPLPSQEQhYuHY4KY8jaXbDddaOkIrnVXaMxg+dRqOxiDyLIMBaOa7d9z1SCwv1VuNZqoAUbNxdzu+ZJYbncAqaBDywUkjtZAtnhcwUDIG2WOU3uh9IKloSNEZMj7MA/btkDf78E9LPhmsigpXiK2Pt2xHqU7XCxMq3VStmuOQteEYaQ38Dujb0Hk3XseHKDE3chfautU7gpZHR9WiiJgKL/GfJwpPiQsgEcvgMySG99AO8nGRwiRXqGntknkD0xoA+DFAfeJxhma6rI542iDBirWwbPYkQJbyu4Wf7SdsFsUbLQTPYCcM+O6IMYNr271JiuoZWjer0UMNae6s6vbjhufBGD+7hvssM11/q2nmGI7YkOP0ZhVrZE5uThTbuCYN5tl6CeamnMmU0T+KaL/dRKU/kdNQzRaY1OkYPcsjQFCLWA8SEh7+aGCnRPCWWb7O9pIRPle+qUPVEJ4cmFNOJFZIl2VVNmcJa6f9pvfL0TgeGV32KdxTmE7UymwIlbBh4SQjlq0jY/saTUYU2TFiIoahNaxjQyPTkUmwPi9BfwwqDFkaqep7v0O0My/U5K1tGlbMd6iHR5dUjSbjLYtYdrR/p/vx+n8pkhMobbT6OjFA6/VQ6cQgp76eAgYJbYcT4JVos0PfR9X1LP27lokr62Fsokpb+j8nlyKCEg0JbPElyFUJZGZTI2DVGq/dHFwPdNlzmLTHvvoPjfR4od+qr14HZFffYvscJwrDZAuV7FfqYisRTHOKaNuNW6ATCD1E9pm0Ks9kuiZoz0cs50+Nr1FLVSo7i6pko20eVhraogtC3tojo7ZVotm95kSDz0pxxR5YOPIZxOInNsbegmWeQRoBFiCfkBnGSoKngM3xP16SLFKN1SnmMxGCYa9LIfyIJyzBtVlSw6cXcUxQySSXNonc2m0dLcvDvv4fsy21+hO9OwYtct6S0XAZFjhT7ymJkLmf79J5HmUlVuJRhlww9G+U6xmDprxMwXTvsdrsoKO1v+JQzUvH8VMBXpiB/1Wb4GLNZ4ARsNhMmfxgzG8+T8j7Q0L2UJQI95UBfZSRTposVJfMwzAd4aq9AQ1tWqFS+nrluT5YKyng/R3N62MWYDP+gf97vVfqr1avGIE8rlAVkOoMw9MMeXHuyFMfsMHc8mUHIpizMCR5D/ooSVfCZyC0K0drx//780Kh+ongcu3Qp1jYLZPc/Di/OO5Pp2XiKNpMZWrn0RVeOw7+uNQvU40sTNzZbhvAnMoDr2tzk7MdjTREh0KMtwh7jQvnnHdv3khSj8zpnjWtvVdLk6ghWU8MX8CVhJAmouInvBcKgmQYwWi3Cy0yIxxe/pWuNTktrupHlcaaWGBf8fJ/tJpzlyyWqB+Tmbc30DB5W/L1dB92sbw0CasM93wuYmNJLvvZXCUiWckTizgBUeFEwFF9n8tzEpKjJLFyY2hBfj3aDSpA20H1pJyABVJl+DcNcZi9aKFbP+9RLJmJdMK8qZspUVlry/ATHdAHUCRSFZxl0f8oqo26rBT9DCpwlzMjjK2chkIiTJL7UVXLWmko0WZYhn+hulsGpG6EftyV1OXdXVWp848hAjGiMRKuvDqoYPLa3lp4Shp6kdomVUKgEtjceOl5aUE2MpUeRU7IHizwzckU9ETWbX6oVr1Qe6eqnHWpJZCwFXCmyywmxWgIlV+gtWKEWUhY6dYG2kCMO5j8es8/MkokrDgQlWtTJKicGvGhNAjO5QcmYnKMrIyvimFCw9KKKFJVoBK4pMG6u4RQj+cbx3h9ptZlhbyGCJHxwQi4IlFIyNfU+Od7BFOsdpQ9EuWKOKFN7ZHTTvZX0YRpEhdKmyODRPL7N6IdtfE189gAOa69Own9gHo83By5pczZTtRVkES9hU6xYtBzl72pO0vORwiTpmUJ9Y5MAp8nJN4e31cOwuqTWZQbTvVXc5ST1KEMZwuOko/3O+Ooa0ZNs0Q/ppJ78205w9pL/bSDDupIVYar19BsZnqM1tZV6cKOywltVNspqGDSYAyKMSmbMkESLTu8KqSr3LJmQe9RcoXMZYeSpLu9KbDZzmWASYRGREkFd7acod8vdjufShsIrOgEeDHQwTKwVo4yJSjE5LEzHpf5qpZTBELMmw9Q6fZj0P07PJr9NoNMfD86mA+h8gM50BHmGoDPpw+Woj4uTKXS7vW4XSmVXjPLdKVprZ3wtFVoIAe/wq7Jc8numY2jOZk3aVzYa2otLoLAWWqJatVFhMenjQbH8vUtwo/II0we8SurZcd7jDakXr0nabXwmf8L7zfr90WxGaQd3oOHfSKpvS6xI7AYXNgvDuioBfakc8LNtfiTevG1jOmKAV2S9zP9fx7uGn7VvgXfc5nhJa0fbmvD4elQx3lk488qWtxPJ+eBioPYDQkVNiXqUeZ2kK1sHLzQJntU2e5d25DH2lkJhPq1iNlB3LtTBnDu2OvHotJS3FfLWA87iSUwcMq9iK7nc4G1rhHEzM5vAsbFqRAQtSpfdN7RoPzHMBAww2srhDwarC98y3Yk0OuUmInZHEZFv75BwcOXgsEpQPVH0FBRgiKeA7fIiWf1MEYgbn4aji8tfL0fqorOap+mpdIzeSp9kM890fUX8xYxdTwbj1zJV/UbJ4i6b2PieJmCOxpE0W5JbR2KPMDznspGPac56oPW1+cCAR2hKm4pFyfEuGmetOaXy4LEzxYacn7TxaLFwLNlC2I4n6Vg8JTuBHEZdjdV1dOhJq3HHW/iHleYMpkZOg26s1LJJHWW9clM9mUyWQ9Fu3LswFgyljFe2fMhM3pZbstrvpvxVUhfvcuu/Uy7SAIntIPLAD/RWG7LCEdNFUja2izZeR7m6pdQsiahZt7vQ466B2ZvR8uo5whti/tpdSXcFvG9LsNuttOfLhn7qnnxbzu92TFS2tl6te+O1uO2XDF1zM3fdCaxRtJ6zsDxvT+bab2lwx4i2ZGVTun7aF1QON/pZLzNrbacH55ksYattIL5mnk479g/Uv8K4/JsaRL9m0nkYd+L20JcbdWYK+R9OOyXJX2vcubWwfRPPMuTbh56xHcZBHTXznCq2Mr8pHyhDDI1KKnO9Qt9pMB5fjjuDfw2nw9GvpIc09t+xuGqmQ+QMf5Ebv1smlQVptMD8S0uxt7Up8a8jLoAQtLF2sExqA/n046SNw2VhsHFcF+4JiGb4WCf4kWdTIwU9MjR28rT7tyWKUUb9gLPIalcR7DME/w895m+yybwdm9R3eDMYPWsmJ0OT7ft9uYLIPzv6yzEVyayjngQSlT+/zyWg7dHxzGPH8bGZhoxHLiUbxHOT2y1D661BPx+Uv7rIcyV/S7YHsXTkYlguWG/OT79cQG+cBXzlIUBMw13ul2P1dNT8TgwN2DAMVaOvwIDiR2JvolEm8x1CUvwmK33qb5EZdXeqX1vUblPfYmNapdMypr5vS2p2bK/ExbfK6y+fzaSfX04aeFYj9lD0hMAPBTVqPLap/AT15L90kScP', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('code-utils', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('crc32-stream', Buffer.from('eJyNVMGO2jAQvfsrRlwIqzQgegOtKprdqlFXUBG2qz1VxpkEt8FObWezCPHvnYSAku4e6osZv8eb98ZWxjcs1MXByGznYDqZTiBSDnMItSm04U5qxdiDFKgsJlCqBA24HcKi4IK2FvHhBxpLXJgGE/BqwqCFBqM5O+gS9vwASjsoLZKAtJDKHAFfBRYOpAKh90UuuRIIlXS7pkkrEbDnVkBvHScuJ3ZBVdplAXeMAa2dc8VsPK6qKuCNy0CbbJyfWXb8EIX3y/j+Azll7FHlaC0Y/FNKQwG3B+AF+RB8S+5yXoE2wDODhDld+6yMdFJlPliduoobZIm0zsht6XoDuriipF0CjYgrGCxiiOIBfF7EUeyzp2jzdfW4gafFer1YbqL7GFZrCFfLu2gTrZZUfYHF8hm+Rcs7H5DGQ03wtTC1dzIo69FhErAYsdc81WcztkAhUykokcpKniFk+gWNoiBQoNlLW1+eJWsJy+Veuubi7ds4AbsZM/bCDTzRHJoh3V6m5w0pJvL9cBRcwDljLC2VqNVAEOjQowcQrsOPUzFix+a+ajWDjoQUVlddr8Hqdbz+qlc9f5zBVdUTu1L99iHNS7sb9aj9P9arfnjBT1Eag6pueK4bOyF8IoeCfF0Ue+QRzM7w++j8TavGj/cPcPJ7ZSoVz7tZ/ivE+8rX6tQiNNJu1EnntA18C9e7oPDOlEghU55bPHNX218oXJAg+cTvRtNLcQePFHwYvvC8xKEPR8jQdSOM6IgopVH1d6A3Izh1zTUM2unkxNheJ2WOAT1qbZwla8f2vczaHU5z9hcTd3Bv', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyNVU1z0zAQvetXLD0QmzFOKVMO6eQQSko9lJRJAgwnRrE3iWYUyUhy004n/52Vv+KEwJBDba+e3u57u1L7r9i1zp+MWK0dXJxfnEOiHEq41ibXhjuhFWN3IkVlMYNCZWjArRFGOU/pUa9E8A2NJSxcxOcQeMBZvXQWXrEnXcCGP4HSDgqLRCAsLIVEwMcUcwdCQao3uRRcpQhb4dZlkpoiZj9qAr1wnLCc0Dl9Lbso4I4xoN/auXzQ72+325iXVcbarPqyQtn+XXI9nszGr6lSxr4qidaCwV+FMCRw8QQ8pzpSvqDqJN+CNsBXBmnNaV/n1ggn1CoCq5duyw2yTFhnxKJwBwY1VZHSLoAs4grORjNIZmfwfjRLZhH7nsxv77/O4ftoOh1N5sl4BvdTuL6ffEjmyf2Evm5gNPkBn5LJhwiQ7KEk+JgbXzsVKLx1mMVshniQfKmrYmyOqViKlBSpVcFXCCv9gEaREMjRbIT1zbNUWsak2AhXNt7+KSdmr/qMsWWhUo8A6zJduFvaJ9EEacieyxaIpR8CYeOcDFKueei8pI2rXSE8Q250SiLqSOzNRaK5gh3b7bPgo9jn0Bn+LU3Dnxpu11O0jhsHL1+C3wMvhnAK67nDkq3i9L8HTqI3OQyhpDiS4tYRHInjG3R0AKJTGWj+G97uaroWMqMMlKd6/wes/oADBRV+V/5FafFIQ5cEqaNBL9MKe2GzbXfQRa+yUtZV0yjo2F2HYDgEVUjpe9iG4Hl3VRfUgZYOn8DXcThv9njXDfpQixk0L74utx7AcY2DzjvsKm31YQ56+EDibS+Mx/5lTCYQLE65lAHloWaZAsPWMJoa5A5L7KFZBI4tXZDVBFJ9e+PaaNCdZq8s8EN8an9sUS6JhKJXrVfNzlxyR4d246e1txXq7UWvS6xV0JslH+fj6ededMQbNj76cDNdrRdl4GfNQ5bgI6Y3dAOf6Lrffzi7LeN+ENvq92v1GfY1ZtxxKvDgdviDi1bRmP/He6B3loCdC2EPK4wC31iKdIebbjtqaDPDfsi4WflpbUylz4eKxC/E1l//GLyJ4E3NXR+PtrmYfilN8/CIutO9bgblVFUVDuDd5btL2IWVRj9R0X52Tk9MVfxGZ4VEitL/YFeeLKjZy0dUiRpUDxqz3xT3kPA=', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('default_route', Buffer.from('eJzlVm1T4zYQ/u5fsc0wZxuCQwJ3MyVNOzne6imEGwLc3JQOo9jrRHOO5JNkHA7477dyHMgLoe23zlQf4mj1aPfZXe1KjU3nQGb3ig9HBlo7zZ8hFAZTOJAqk4oZLoXjnPIIhcYYchGjAjNC6GYsok+1UodrVJqw0Ap2wLOAWrVU89vOvcxhzO5BSAO5RlLANSQ8RcBJhJkBLiCS4yzlTEQIBTej0kilInC+VArkwDDCMkJnNEvmUcCM4wCNkTHZfqNRFEXASpaBVMNGOkXpxml4cNTrH20TU8e5EilqDQq/5VyRg4N7YBnxiNiA2KWsAKmADRXSmpGWZ6G44WJYBy0TUzCFTsy1UXyQm4UAzViRp/MAChETUOv2IezX4GO3H/brzufw8vfzq0v43L246PYuw6M+nF/AwXnvMLwMz3s0O4Zu7wv8EfYO64AUHjKCk0xZ7kSQ29BhHDh9xAXjiZyS0RlGPOEReSSGORsiDOUdKkGOQIZqzLVNniZqsZPyMTdl4vWqO4Gz2XCcJBeRBVCmRCwLfRtjwvLUXEjy0fOdhzIPd0xRYA10QORp2n6WnZyRqIq4596eoEDFozOm9Iilrj8Fhp8IdHIWHChkBnvE5w4/KTm599wwG6UZy3gQp3PwCnmGZiRjzz1BE2bHUlGG4kubTIt8pqD5d5zXf80UtyBvz2/PcdfkE8FI+Yo6b6deaqlDs9rCE2+6I7hmKXQ60Gy1/HJlGo6ZWlMerdeMW32BkR/zJEHl+QGtxldUjrut0yPPr8zY8Taz0sAyu1cZ7vjPay8cZzxR0KFFTVZKhcEhKkys23v+epLtFTVKFovChQkdUM+ieGenzX+pTLa3tri/AFtkV4ZAFkvM9mALPA6b8P6DX7c/7ZVNPAGPNv4zV5YCtJ6KHY0GHE5rAMoieBVkzf9kK+Lx0RZGMEZyN4Jf4YXT7oe3Sa3yWc+pDFNZfw/UuAyqhEW4P2es+TfG6jBluP8vCMLTatjteFqRLkpeZtN/01+inytBSUND6Xya6zwpF/lkfd+JRjyN59tMKbjNlIyoZ7p+gBOMjukG8tzGgIuGHrl1+NOlz1/VuSk3BNpQA1SBFJ4bM8MI9MzAi3wK7NMynKjQR5Ft120vitdrsRdiuWurAxEFt09hF0Mqp1X9XAT2CiLiPKO8kOPwCHRBZVAFg6as+Ao37oMteNhodjq1aqkG797Bxl4puKuBtZyRIQMb78kSPN24NwIn3NwId8Fswbg5IvmsvmdpWXY6INrjaeW4LvxW9n3YXzx+a/a8nLVm6fN8rgc6/n9nWqDRdCXDNgV9O6Fo2h6yLulVRnvH/7V8anrXRSOvykyQpcxQ+x/PkhkxerC49KLYbbn7z91gLOOcWjw9dqQy9jJ67cnx0nIG1I2+tuf0lX3iLX2rjeQNbQk9BOk0Vvqmspgp4vSWieXzu2KAgvMD3gx0hA==', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('heci', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJztVl1v2zYUfTZ/xa1QlFLryHHeasMb3DTFjAUOEKcNCtsYaImyiMikRlJ2gsT/fZeS/BUnK7Bub/ODaV3ej8N7Dq/cek/OVf6gxTy1cHba/ggDaXkG50rnSjMrlCTkUkRcGh5DIWOuwaYc+jmLcKl3mvCNa4O+cBaegu8cvHrLC7rkQRWwYA8glYXCcEwgDCQi48DvI55bEBIitcgzwWTEYSVsWhapU4Tke51AzSxDX4beOT4l+17ALCGAn9TavNNqrVarkJUoQ6XnrazyMq3LwfnFcHRxgkgJ+Sozbgxo/mchNB5w9gAsRxwRmyG6jK1AaWBzzXHPKodzpYUVct4EoxK7YpqTWBirxaywBw3aoMKT7jtgi5gErz+CwciDT/3RYNQkt4Ob366+3sBt//q6P7wZXIzg6hrOr4afBzeDqyE+fYH+8Dv8Phh+bgLH9mARfp9rhx0BCtc6HodkxPlB8URVYEzOI5GICE8k5wWbc5irJdcSDwI51wthHHkGocUkEwthS+LN8XFC8r5FSFLIyDkghzL2JVvwgDyShkHiotTPtYoQWJhnzCKARUAauNmIGAKiCbZyZmLaQUtjyTS23kIPxtPuxhClIovRVHPi09LwR52VBiG/59EXFI9PWzMhWyalTRhTXKZBmaT0D42NVWFx0ZiL0uMdJX0aM8swensePwrgsZRnGfihB1Fo1QjZk3M/6ML6WQUhQ6cH7nv53RzVkSjw4AO4juDiwRNgFjqZSOq+nyga2OoOKBZhPYOkWf/taRNsEybeKGVOgZdiZgAPuxQxjzsTvD4gEp/1emcOWhVjx2fTJmRi5uIqnxwhWmcat6eIE9Z0W/yJ1hDq4o8uYV283cQ+G5cmNAoT/dJ2Vapkb9tVoonk98JOpLd/+BUT9gLNftDdMWmw1c+7H2LzFn4QVgUxGa0iUBm+ixLuUmFo4IxOJ40GwnuDlrGYYgKmrblFxft1UykCpYFDGSmJN7HgiLIMc9mWiODReXagyrAuizV+WlR/o6p/TVYv6IpudXWSoWy20nJk4lTKS9sy3LM6iid0T19IsVV3TfBatZbwacymvZ53GOsdMT/ZUk8PAD7jvrEMMxWVE+N1/itPvOxhXpjUX1aGkjg0Flr6uFTGmebsDn+5WV4NjQxpvncjA+pPFQL+ls6FksIqfeJahWzOucV7NMCHajoF3V3sJv2arPcmWcrMJyGZfvCRfjfNnKtI4GiawZveBhC8ewcvbm+GnOvoBmrCMsMd12Xmnx90ZXde1uTR1j/V5EGi3axbpSJKy0GHsNyc258Qu5h9mWzOXE37VzRS9m4fP7rKIssqy45zp5P14Uvov+XOgfifuh9R53nw66v7nT0mf8wtWai4yDi2Ef+EWvdacSR3n5nD7aVFh+3vI6+dPuo8G7+/AMatccs=', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VcFu4zYQvfMrpr5IWmil1HuLkYPjuKjQhV1ESReL7WJBSyOZjUyqJBXbMPzvHUqyIyPe8mJJfHzz5s0MHX9gM1XvtSjXFsY34xtIpMUKZkrXSnMrlGTss8hQGsyhkTlqsGuEac0z+ul3QvgLtSEsjKMb8B1g1G+NggnbqwY2fA9SWWgMEoEwUIgKAXcZ1haEhExt6kpwmSFshV23QXqKiH3tCdTKcsJyQtf0VgxRwC1jQGttbX0bx9vtNuKtykjpMq46lIk/J7P5Ip1/JKWMPcsKjQGN/zZCU4KrPfCadGR8ReoqvgWlgZcaac8qp3OrhRWyDMGowm65RpYLY7VYNfbCoJMqynQIIIu4hNE0hSQdwf00TdKQfUmefl8+P8GX6ePjdPGUzFNYPsJsuXhInpLlgt5+g+niK/yRLB5CQLKHguCu1k47CRTOOswjliJeBC9UJ8bUmIlCZJSRLBteIpTqFbWkRKBGvRHGFc+QtJxVYiNsW3jzPp2IfYgZY0UjM4eASshm94NntfADdmjtd8WNfixX/2Bmkwe4A68FfXQgb9JCert9D19RWuMF0dw9zCmwRR1lvKp8RxOC1Q0G7Rm3okwjt9iCfa8lDDrGLlyUYyEk/qkVJWX3PcfINDX1Mrk/CuEAr7xq8PZNQ+Hi445qZNK9zHwvfuU61o2MXYA8Mip7QesFcOxjiaIljs60ncDDWWbnQEYlkZbyP0eSjqbPYaakxNZD/wA1t+tb+EngEDZoec4tv72wEo4hnOvgv5n0puOshYJ4jsAbnsjWjXwJLsCXR90iRbCqSIiZXN1rVk1RUIvcgWyq6jrGqhdqHYK0ESOrUpoGWfpBZKhtqZB/y1MZh0sUdJG0R6MKZUlXwt0d/BpQBducGmnWorB9GhM4/h9BjfjiB/ALNaPnGN5k37cPUaHV5gxWtR9cZcSKZuoAQ9w1mJs632Uu3IXRoYN3qPdmu9WZTcK6Y9/E95NLcM0kt1o7NNoIN+I0Fq7RJd9Qn3eE326+0zDta/owzLjfHNOmt8YddSc1Z/5MfwGfxvdzPwhP03Ll0KefHToPynBdujREDJ+Hk+NScj7Qpw5wZEfGNipvKqR5daPnfJK4vbiFJv8BYJoQOQ==', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJytVN9P2zAQfvdfcaqQktAuKbyNLg9dKSLa1CJShhBFk5teW4vUzmyHpGL87zunPwaDxzlSLN99vvu+u0uiYzZQxUaL5crCaffkMyTSYg4DpQuluRVKMvZdZCgNzqGUc9RgVwj9gme07Twd+IHaEBZOwy74DtDauVpBj21UCWu+AakslAYpgDCwEDkC1hkWFoSETK2LXHCZIVTCrpokuxAhu9sFUDPLCcsJXdBp8RoF3DIGtFbWFmdRVFVVyBuWodLLKN+iTPQ9GQxH6fATMWXsRuZoDGj8VQpNAmcb4AXxyPiM2OW8AqWBLzWSzyrHs9LCCrnsgFELW3GNbC6M1WJW2jcF2rMipa8BVCIuodVPIUlb8LWfJmmH3SaTy/HNBG7719f90SQZpjC+hsF4dJ5MkvGIThfQH93Bt2R03gGk8lASrAvtuBNB4UqH85CliG+SL9SWjCkwEwuRkSK5LPkSYameUEsSAgXqtTCueYaozVku1sI2jTfv5YTsOGJsUcrMAYCKmz1ecbvyA/bcFF8swC+0yohZWOTcEoM1xDF4uZBl7QUNaAt164lrCiLyOcT7JvheY/i5i+IFIdaYXdC0+F40EzIyK68D9x5tDzRb+0jNpdBYIqxp0xTQ83pvzUr63pxbTvcPEvwsgOdmIptb7Riy0KqUGiaXftCDl49yqNJ+lMOZ/1sOIUM3a6Qas5WCo6v+5BJ+A68eYeo9wwZN3O0Bjw313vpH3Q7MOtA6o+/Ntd2v45Ne/SXmvXa7dtnFwp/d1w9x3IoMVbHlbC7GCaWnpyAu1hnoOPWmEmthp9J7R6ziwg7JR7TZwdU0nWuD9O/w/y1SSDLXfhC4KegGhzt/Z8Ct/cgYtCiffM+JpQruzWS739oeoA3eWSPhNbkXtn2/MLZW8zJHGhr6f1lDLToMKTFmfwBvrI8c', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	
	char *_notifybardesktop = ILibMemory_Allocate(28225, 0, NULL, NULL);
	memcpy_s(_notifybardesktop + 0, 28224, "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", 16000);
	memcpy_s(_notifybardesktop + 16000, 12224, "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", 12224);
	ILibDuktape_AddCompressedModuleEx(ctx, "notifybar-desktop", _notifybardesktop, "2023-12-05T11:01:21.000+01:00");
	free(_notifybardesktop);

	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('eJzNGmtz2zbyO38F4g8V1aiUm0839mRufI4zp7vU7sRuch2PRwNTkESXJlmQlKxLdb/9Fi8SL1J0nHvogy0Bi93FvrHA9PvgPC92NFmtK/Tm+Mc/oVlWkRSd57TIKa6SPAuCD0lMspIsUJ0tCEXVmqCzAsfwT85M0CdCS4BFb6JjFDKAIzl1ND4NdnmNHvEOZXmF6pIAgqREyyQliDzFpKhQkqE4fyzSBGcxQdukWnMiEkUU/CoR5PcVBlgM0AX8WupQCFdBgOCzrqriZDrdbrcR5lxGOV1NUwFVTj/Mzi8ury9+AE6D4JcsJWWJKPm9Tihs8H6HcAF8xPgeuEvxFuUU4RUlMFfljM8tTaokW01QmS+rLaYkWCRlRZP7ujIEpLiCneoAICKcoaOzazS7PkJ/ObueXU+Cz7Obv179coM+n338eHZ5M7u4Rlcf0fnV5bvZzezqEn69R2eXv6K/zy7fTRAB8QAR8lRQxjswmDDRkUUUXBNiEF/mgpmyIHGyTGLYUbaq8YqgVb4hNIONoILQx6RkyiuBtUWQJo9JxRVfutuJgu+nQbDBFES2vOFCeou+7E+DYFlnMVuECpoDPjLLQE44Tf5JaEgnD+PgC1cOU300B8ZhHT01hh5g6OE02Gu4VqT6mOfVzwJlmN83eLZrMB82EBWgg0yBjPmkAGEfAACsDpggvOd/KalqmiGO3KRONrBiXoI5ghHRcEFKZiPzGKcpAZOvMAX+FEMKzRc0v7p/IHE1e3eCRiaK0QQx5CdyaXSfZAsL7RjtvVyAJsHYQBthmdc0JkCDmSD7eokfG274sPjKhhVzzZooz0LvqoiA1gVDfkyCq5YtsV+myTzdkEWoSDHbAFk/MgXfjtT06E6InBlkyEBwwpwJ0NePsL3S1hvHEBV1uQ4bmFuc3I11zQnD+cf1h/eCe+a5u7AdnQg0nHOXb6YjjW8NmbTgaD6PwcoWP6ufsCYkJjZGV6AKscIEy2NwTM5TOAJIXENwveCRDtaAEYwUBTX5kaOASTAZ9Br97frqMmIxI1slyx1gNokqd5BY3sO4uQtlgKACRWqk+Zocgln2U3fCBGI/zXDKnNqwY8WwAoBNyKETvnQi4jcBiZ6gJU5ZSiCU5rRsfjYAZ3QFo7d3E6Swned1Vp2g4wma18UJyuo0RftT6VY8MofCk8rROLpgXy5AtrA2Yk4TmrxLExHMRwuyTDICEoMwVwnjmKAjIxgcTRqzaw2QfcD0T1Aj9XAMMlFeLkjWxfgU7SfGotJctMFpLaOSnwj7JEsJiF69Fbv/7jukSKC3YmzsLHMRsc90ij5DMqQE0i1K82wFERxSDuTzNc68Kxh5U4aNYSqGXOLdDLBPnBJMZ4+PZJHginRhl6ryfbr4Eez41+2dUXeklSriEjcxtfD7IWYEoTumSVHl9CdS4QWu8GBbOmARys5c8wdEig2f9UNw+fP8fZKJzPuO3NernyAYQcofjS1xfwPDddkrv5q9iVCIzaSjEcsyIKGN/iUTqy7bllm+wIg+LDXJhNSDNSPbD1C5kYzQN0AgbCnw3YoEyr+ew0bvcfybTXk6jaGKylMSpfnKQDiSKwWSkQiVUxb7OSPiN/watWGznW2GNFnxkqzxjmaYuXZDiEWSNiOzGPNKp6ZiTou+w5YZHWPfWuadeMRtqTRZhvTVWzequOYluINQPxf+8IkZSNhuYYJop7nw9XQHMZtjoeQRKt6zNFUaKDU8LIqjGEONhsInFuafiUaUEn1o9oFmFD6lSBRMCaEp2zYny9zwxx+oG4In2/G41wAUux3qbdJBfxJw1eUL+j2h3qThC+x7P1+FXut3s8NdggV66xRh4HDZooUWB8hTUxBV1M4WiiljxeHM6c+alvC8ODvypZ9+V6bcd4h43x81NAP9qqDxgoDx/+TG3SKCzFeluoReIJLbO00Ee5moIqvCtVKWFAMLzk2mUscz6iTFxplaLpvy9lTbp65rGV1OzckGgeMjvYmXffhBUA47R0WDSzsJtGbYnR3Grgua8nf5EyfOg4gt+8RftbKVMQGhdrDYnpc9x2X/kr6daWfpO08wwUMAu7yBL05JtqrWzB/eMBWxsdsf70S25zrbFSRfhnJ8zB0n5yX2SIPXT7DaEbZLj7zlQJ8V6BtC7MBvHIRtiGpNstBqdkzsLsJz1drYieH12BP6FGDYxBc3Msh6z4kHjLfcjgdi8BvFgz5/f3E4kOFYAzjoDcP8u8e4D3qAliVVyT3M6piAQ+otLdq6rmteVHXMQ6g31ffHOf8aduBr6422kTVpBXt73LH1Qfbbbbv7vgQ2y1i32jJce86xX6aMjXTk3gisayTctJFp88ygM50iHhrG0knA4LHqibHOLNoSlMlrA0l9KgSMksoMX8a5MzYPOLo1OQ1JJ/fLBu6QNXYS83EhPXA4FyK4fCUXgyInb5UNPZB4dZTl2Q+qAypST4e6+L2HguR3UpbiGhvubhiX4ab3hGrs9NAmFskiG1WqN4SzHRAXN1GM+4e6rBi7BV6BQ3PmeUOlREvgh//m1znpjt/6CB79+/nfWaFdXOiRQpTkbVDgDRlfHKCVPypb0ZhWfcc2yH72kcwHP3aSY48bWRdKImryXUTsr13ga7ccS9YyS3d6SPRu38uBir7PZ0CTPrNBg7xeDMkqyFNTKKjeHN0T/7wcN0i9XJt2JJjQGXSZ8DTAPYc3d11jcAftraUUerPxC5sFw3oFex+qnuD0VebcyHqAbjTq4kq5+sRbLRnZ2pdc2nWyhkqsMO92m2rerW171euk9xv2SqGJ/7hEOKUEL3aotXyIvIClRLD/+DdGh0XZNc4WKaGeusA5tdCmZNHqvkHFi9hXSDfDOqkc9GCF072eC3vTIegO4B6vlnrrSh32tNP6GEStsVMPNb1QeRY190bJSeE9EuzcNr8qsaeBc7t6cFl4dj1xKOJ+S90ciiDfSjO+nsSh4/ehorv7YOI7o/+HN2mfvcx6ir2l4ViMyAgBRCJv07nI53RnZWrtJUF7a9clB72+a7n2QDunAafsE9qSvVbn8Y4dGHu6Dp7IPhhQdSLIXSesOMXqqc8+59qw9olXSB7C8Kv+TKRfHqJrDKcQSpYEom5MxHs3yEni1KKpWrzEurUwz9e4XJ/nCxKO75w008m+XTL67qxNb1oQxr/NhkZcM2ND7713641cjiYavc5rdKvjYTzT8Mja7a77m2i2NMLua+YB12Ymk8+4Luu/KrN7UsPvvMTtFe8ree+bhnE+5K5q2B2VthNpVeYpsi5O+wGMsNgPWyggL1QnqWeQ0Hzs5TdYL7y9Mq+PQM7qKK6aHW6zzXjS563NtcPgBD1wYlLteivXfvrX//LP14G13v11VyiiG+nWUVpnsn1ZIzMjZMVWFrw/Z4iCv+0bo/+GJF4sBZlwXygFyP+6CFg5IA2a2ZtlFN1yIOIw6E/qc+12Ar7a2ai5t+TTpTOt8QMQ2i8HcpFnpOPiEjyZvTuE2eNTMwmYCjI2b25GmwL1iLuiw9mJZfY6Zm9E7ePc69cg0pYxXtaZ25U3bAPej7Wb979cECDNBbFDqbvE1osCsKmebb7HSVpTYm/zVcveN9yIvNliHHWybngQy36uaJnYj21FW8JyxWS+JYf/wqeCx3xRpyQiT0VOKxYEmsRhzkRmM0W9sGoGOuCbZ+HNgmbEWQF1Fq7TinVSdP/WhlunbVONyg7MDdWYjJLMcdH+31mk3Ek=', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	
	char *_servicemanager = ILibMemory_Allocate(35605, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 35604, "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", 16000);
	memcpy_s(_servicemanager + 16000, 19604, "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", 16000);
	memcpy_s(_servicemanager + 32000, 3604, "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", 3604);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2023-12-05T11:01:21.000+01:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('update-helper', Buffer.from('eJytVU1z2zYQveNXbHwhlSqU66M1OaiOM+U0I3csO5600/FA5JKCSwEoAEZRPfrvWRCURCp0k0NxIYD9evt2F5y8ZldKb40oVw4uzi/OIZUOK7hSRivDnVCSsQ8iQ2kxh1rmaMCtEGaaZ/RpJWP4iMaSLlwk5xB7hbNWdDaasq2qYc23IJWD2iI5EBYKUSHglwy1AyEhU2tdCS4zhI1wqyZI6yJhn1oHauk46XLS1nQqulrAHWNAa+WcvpxMNptNwhuUiTLlpApadvIhvbqeL67fEFLG7mWF1oLBf2phKMHlFrgmHBlfErqKb0AZ4KVBkjnlcW6McEKWY7CqcBtukOXCOiOWtesRtEdFmXYViCIu4Wy2gHRxBr/MFulizB7Su19v7u/gYXZ7O5vfpdcLuLmFq5v5u/QuvZnT6T3M5p/gt3T+bgxI9FAQ/KKNx04AhacO84QtEHvBCxXAWI2ZKERGGcmy5iVCqT6jkZQIaDRrYX3xLEHLWSXWwjWFt9+mk7DXE8Y+cwPaKDJDeLsnL47aq4gqzopaZt4HWMeNi2udc4e/c7caseemSt6HQUf2Ejd7b/HBLKbcxqTwNILnpl+SR7ppotnp4eKpuXiawo5ieq+igPjVAdC/Qr8xyCmHaJQI+4fQXSDeMyFoHMejqd/Xpons6LRr/LVyng+k2/PuN13n00HzhKiUxyQfg8EKKypCTP405qPGMHC050n/zyztmQoREz+JNqlQljR3r97Cz6OD1hGHX7rxFkf3kpoPM9/PmaLnQjrrR4PcNVMddcL41YbJKkXYO7LdYYeVxRdiOrPtnfvSgCpH67qVKSxVJCPeHT7QuOLC0X7dKQ/8BNFjLQOwaEzkFRUv7SVEm2XUo6mP06+Mu2wFMY6+A+ulrE/IxAHRvhP1fwIJeSe+KSh5PR0SBhAkDptBHSXjqEFJRBw769BRJ3mESx/0MDinfLUWJbqW+G6f/Xn+1yjRQmMcwg/2wykBu0D2yfjEp7PS7ZV+QfqtUctKyL8XW5l9O7LDFv5/857gn9ic9tEPehuM3/c1SEvTet3OO03SDfdUoPMFokMZo1zJw+Du6Q7xjnxj58lsojSlZ8cQ7ePJdoytVV5XmNBDoYzzT9Jz+BVchg/spuwrTiqBbg==', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-descriptors', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-dns', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-language', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-pathHelper', Buffer.from('eJytVU1v20YQve+vmPoQSqlC2WpPMYRClV2EqCEVllMhQC4rckhtTe6yu8vQQpD/3pnlR5Q0ReGigkFDu8M37828Gc1firWpT1YVRw+Ly8UlJNpjCWtja2OlV0YLcadS1A4zaHSGFvwRYVXLlP71NzP4Ha2jWFjElzDhgIv+6mJ6LU6mgUqeQBsPjUMCUA5yVSLgU4q1B6UhNVVdKqlThFb5Y0jSQ8TiXQ9gDl5SrKTomr7l51EgvRBAn6P39ev5vG3bWAaWsbHFvOyi3PwuWd9udreviKkQb3WJzoHFPxtlSeDhBLImHqk8ELtStmAsyMIi3XnDPFurvNLFDJzJfSstikw5b9Wh8V8UaGBFSs8DqERSw8VqB8nuAn5e7ZLdTOyThzfbtw+wX93frzYPye0Otvew3m5ukodku6Fvv8Bq8w5+TTY3M0AqDyXBp9oydyKouHSYxWKH+EXy3HRkXI2pylVKinTRyAKhMB/QahICNdpKOW6eI2qZKFWlfGi8+7ucWLycCzGf0x+8wZLehcpkTUkOoPJU8hGhltS92pqUyDF+SkBUANQeDtgiaqhL6YlZ5WJG6tHWFqVHotABcMW4yk3AkIMCqmC4nvDzajoLLtKywu5kQSekAdojhhoRp85vCOvGWuawN/aRIW+o36k39gQTClnvb6ZMJG90ytKDlN8IsUs0C1kXTKcL/RicpvLhZfhuCbopS3jxYozhiC6OPyQxyfs7NsUoqMO+4jNVaGP5hDUoT4NAiEpT8WQ2Ckl7IX2JIwdtLykbJInzrHuMLPebI6gennvEOCXKnAxScodpknqdnJn6Q1Oowlhy5IDfBY/YHyQX+JFsAcuBTZy22WQaO/KjnwxnQ79huYSoVfqHRQQ/QfT+fQSvIZpHtCEGzA4vrk09+cZp4/p+PDdBBzi9hhGyq/lygP6DyvNcvp/EaILgjth5ab3b03hOojiafsMBX/XCNQfnlafFADE+nS2+z27HJ5qcsFmpGSHNiDckvoq9uTMt2rV0SMVHnQ0kCJR4wMdRbl89zsvzNbns3RfTFBWU/BX8SFX69FWZvu9eXAy6+Ymlw38V6IeFQM6yWNHOCfK8laoMjsWwbdB2xqPVizobZo0i+WdB06LyIGkS+NXxDQcHmT6GJHS83X3ecSHE/6NR/4t/nmvQxdnd/+I0flr0jdXD6rsW5L9u91Kb6bfas7phbV0LIf4C0Zl7+Q==', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-service-check', Buffer.from('eJy1V21v2zYQ/q5fccsXy50rp9m3FhnguSlqtEm62l0Q1MVAS2eZq0xqJBXHKPrfd0dJtmQ7ToathGGb4vHe+NxzVP9ZMNT52sh04eDs9OwURsphBkNtcm2Ek1oFwXsZo7KYQKESNOAWCINcxPRTrfTgDzSWZOEsOoWQBU6qpZPuq2CtC1iKNSjtoLBICqSFucwQ8D7G3IFUEOtlnkmhYoSVdAtvpFIRBbeVAj1zgmQFSec0mzelQLggABoL5/KX/f5qtYqE9zLSJu1npZTtvx8NL67GF8/J0yD4pDK0Fgz+XUhDAc7WIHLyIxYz8i4TK9AGRGqQ1pxmP1dGOqnSHlg9dythMEikdUbOCtdKUO0VRdoUoBQJBSeDMYzGJ/DbYDwa94Kb0eTt9acJ3Aw+fhxcTUYXY7j+CMPrq9ejyej6imZvYHB1C+9GV697gJQeMoL3uWHfyUHJqcMkCsaILeNzXTpjc4zlXMYUkUoLkSKk+g6NokAgR7OUlg/PkmtJkMmldP7g7X44UfCsHwRBv08fmPAx0kfQialErywsMMv9BuHoWZaBM2vOW4KOrajSO4vmjtSBEsuti3FhDCqXrcEUyjtWibGxyuANqzToCqP8Hq+gQsGD+0HOQTqIKe0z3HqS9EAVpE5zMlfSejvzQsUcOQf0Z7V/uMD4a9gNvnlw3QkD9tXmr8EUzmv4hB3a9pwe8XmvO92tWC7cYju7E1mB1u9Lo98LNOt3uA558vbdxW30XsciuyTgkpc96Iyv30wIGBfT6XWOCsa6MDGycq+PnC5/6DQQLtEuBimlocy+0mYpMkqJSBI6pdozIAH6lopOhlMnZgSG7So726NqIgHraLvHAji5xNqi/6W0hmUkkS1mX3Ftu/55mScefLQhByy5cA7JtuV5kAOteXu1EXH7EdxQGIb4RBVLZNqi8xeMvyop4LNiIaMQqQpliZ9NyD4DPYY/xHzcGwo6ZKoGe42vpVBUUYZxbtHDjXV/GL2mFUfq7GbehirkRsdUwU+J0DZRVhl+XhnudKPqX5SiG5eLO0fzWX6p4Ngcch7aSNpLDLvdvcX9zD/gW5UWzwabmiPusMyRsEJfeo2qJdYqMrcfdqVnOw5K2CjOtCWP98PhUdl5Uvjf955gZveP/HAijvjR1tuexQwJCO+7R1C+3VH++16XOnxSvi8R0uYEQippjzCGc5M0+jVl9JuMUdHPv6Ke2/Hk4nI6HZaAHWriDZ2N0U2nFcxszXKPs0EDOWW9xrrIEtVxe7G0SnNF9Iw7dbwlNivuKByp5vzA8xSVctGmrl7Trkdkx3ADZI6gTP5VWLfhDdywxk6V25Idqn5G9VZ4+zNDXZ2JjjHvmrE2WfBHkCBlsBVGpvVXJm32He/Rs7hnYKTj3MaXbNrqrkq/4f8DxnTagZ9hrwxp82hJXPWBrHV2audApYT3RyvFy5FxqQo8pquKjX8iS3clF3YiStKuA8SHXiRDlbrFry8eM12p9Zs+n36heA+qLVWXYhHh0jh7Q/0l7Jx0ul341vaumPFlUaXhi+6rAwxVuQjn53X7YIsxp/O/U/ho3ryfdewWSM1Otnl4uJ31uMCoiMpGWre+bXOkuxhfG+lmyfflh9rAwce7dXE8Th4/pm/W42j/fNw57+DxdlaPI23NH5wr7+H+mH56UNM+nJ7oxuGNZYUiHo79cNz7mh7qlnXv4+86fL6xlxHv9Q/fNPxbbE1w1DYt3ePIxbpScmoI3Cnqy3ws6B2JL+2/nHVebgwvdVJkSGVFL8COAbT7MrDN0cygqKYJzgVda46o2bxchFz0OyF939VJ3v8DfZxReA==', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('wget', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('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', 'base64'), '2023-12-05T11:01:21.000+01:00');");
	// }} END OF AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {get: function() { return(require('wget'));}});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {get: function() {return( require('os').arch());}});");
	duk_peval_string_noresult(ctx, "addCompressedModule('code-utils', Buffer.from('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', 'base64'), '2022-12-14T10:05:36.000-08:00');");

}

void ILibDuktape_ChainViewer_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[0];
	void *hptr = ((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[1];
	int top = duk_get_top(ctx);
	char *m;
	duk_push_heapptr(ctx, hptr);										// [this]
	if (ILibDuktape_EventEmitter_HasListenersEx(ctx, -1, "PostSelect"))
	{
		ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "PostSelect");	// [this][emit][this][name]
		duk_push_int(ctx, slct);										// [this][emit][this][name][select]
		m = ILibChain_GetMetaDataFromDescriptorSet(Duktape_GetChain(ctx), readset, writeset, errorset);
		duk_push_string(ctx, m);										// [this][emit][this][name][select][string]
		if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ChainViewer.emit('PostSelect'): Error "); }
		duk_pop(ctx);													// [this]
	}

	duk_get_prop_string(ctx, -1, ILibDuktape_ChainViewer_PromiseList);	// [this][list]
	while (duk_get_length(ctx, -1) > 0)
	{
		m = ILibChain_GetMetaDataFromDescriptorSetEx(duk_ctx_chain(ctx), readset, writeset, errorset);
		duk_array_shift(ctx, -1);										// [this][list][promise]
		duk_get_prop_string(ctx, -1, "_RES");							// [this][list][promise][RES]
		duk_swap_top(ctx, -2);											// [this][list][RES][this]
		duk_push_string(ctx, m);										// [this][list][RES][this][str]
		duk_pcall_method(ctx, 1); duk_pop(ctx);							// [this][list]
		ILibMemory_Free(m);
	}

	duk_set_top(ctx, top);
}

extern void ILibPrependToChain(void *Chain, void *object);

duk_ret_t ILibDuktape_ChainViewer_getSnapshot_promise(duk_context *ctx)
{
	duk_push_this(ctx);										// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_ChainViewer_getSnapshot(duk_context *ctx)
{
	duk_push_this(ctx);															// [viewer]
	duk_get_prop_string(ctx, -1, ILibDuktape_ChainViewer_PromiseList);			// [viewer][list]
	duk_eval_string(ctx, "require('promise')");									// [viewer][list][promise]
	duk_push_c_function(ctx, ILibDuktape_ChainViewer_getSnapshot_promise, 2);	// [viewer][list][promise][func]
	duk_new(ctx, 1);															// [viewer][list][promise]
	duk_dup(ctx, -1);															// [viewer][list][promise][promise]
	duk_put_prop_index(ctx, -3, (duk_uarridx_t)duk_get_length(ctx, -3));		// [viewer][list][promise]
	ILibForceUnBlockChain(duk_ctx_chain(ctx));
	return(1);
}
duk_ret_t ILibDutkape_ChainViewer_cleanup(duk_context *ctx)
{
	duk_push_current_function(ctx);
	void *link = Duktape_GetPointerProperty(ctx, -1, "pointer");
	ILibChain_SafeRemove(duk_ctx_chain(ctx), link);
	return(0);
}
duk_ret_t ILibDuktape_ChainViewer_getTimerInfo(duk_context *ctx)
{
	char *v = ILibChain_GetMetadataForTimers(duk_ctx_chain(ctx));
	duk_push_string(ctx, v);
	ILibMemory_Free(v);
	return(1);
}
void ILibDuktape_ChainViewer_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);													// [viewer]

	ILibTransport *t = (ILibTransport*)ILibChain_Link_Allocate(sizeof(ILibTransport), 2*sizeof(void*));
	t->ChainLink.MetaData = ILibMemory_SmartAllocate_FromString("ILibDuktape_ChainViewer");
	t->ChainLink.PostSelectHandler = ILibDuktape_ChainViewer_PostSelect;
	((void**)t->ChainLink.ExtraMemoryPtr)[0] = ctx;
	((void**)t->ChainLink.ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "PostSelect");
	ILibDuktape_CreateInstanceMethod(ctx, "getSnapshot", ILibDuktape_ChainViewer_getSnapshot, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getTimerInfo", ILibDuktape_ChainViewer_getTimerInfo, 0);
	duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_ChainViewer_PromiseList);
	ILibPrependToChain(chain, (void*)t);

	duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));				// [viewer][process]
	duk_events_setup_on(ctx, -1, "exit", ILibDutkape_ChainViewer_cleanup);	// [viewer][process][on][this][exit][func]
	duk_push_pointer(ctx, t); duk_put_prop_string(ctx, -2, "pointer");
	duk_pcall_method(ctx, 2); duk_pop_2(ctx);								// [viewer]
}

duk_ret_t ILibDuktape_httpHeaders(duk_context *ctx)
{
	ILibHTTPPacket *packet = NULL;
	packetheader_field_node *node;
	int headersOnly = duk_get_top(ctx) > 1 ? (duk_require_boolean(ctx, 1) ? 1 : 0) : 0;

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	packet = ILibParsePacketHeader(buffer, 0, (int)bufferLen);
	if (packet == NULL) { return(ILibDuktape_Error(ctx, "http-headers(): Error parsing data")); }

	if (headersOnly == 0)
	{
		duk_push_object(ctx);
		if (packet->Directive != NULL)
		{
			duk_push_lstring(ctx, packet->Directive, packet->DirectiveLength);
			duk_put_prop_string(ctx, -2, "method");
			duk_push_lstring(ctx, packet->DirectiveObj, packet->DirectiveObjLength);
			duk_put_prop_string(ctx, -2, "url");
		}
		else
		{
			duk_push_int(ctx, packet->StatusCode);
			duk_put_prop_string(ctx, -2, "statusCode");
			duk_push_lstring(ctx, packet->StatusData, packet->StatusDataLength);
			duk_put_prop_string(ctx, -2, "statusMessage");
		}
		if (packet->VersionLength == 3)
		{
			duk_push_object(ctx);
			duk_push_lstring(ctx, packet->Version, 1);
			duk_put_prop_string(ctx, -2, "major");
			duk_push_lstring(ctx, packet->Version + 2, 1);
			duk_put_prop_string(ctx, -2, "minor");
			duk_put_prop_string(ctx, -2, "version");
		}
	}

	duk_push_object(ctx);		// headers
	node = packet->FirstField;
	while (node != NULL)
	{
		duk_push_lstring(ctx, node->Field, node->FieldLength);			// [str]
		duk_get_prop_string(ctx, -1, "toLowerCase");					// [str][toLower]
		duk_swap_top(ctx, -2);											// [toLower][this]
		duk_call_method(ctx, 0);										// [result]
		duk_push_lstring(ctx, node->FieldData, node->FieldDataLength);
		duk_put_prop(ctx, -3);
		node = node->NextField;
	}
	if (headersOnly == 0)
	{
		duk_put_prop_string(ctx, -2, "headers");
	}
	ILibDestructPacket(packet);
	return(1);
}
void ILibDuktape_httpHeaders_PUSH(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_httpHeaders, DUK_VARARGS);
}
void ILibDuktape_DescriptorEvents_PreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL) { return; }

	int i = duk_get_top(ctx);
	int fd;

	duk_push_heapptr(ctx, h);												// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);		// [obj][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [obj][table][enum]
	while (duk_next(ctx, -1, 1))											// [obj][table][enum][FD][emitter]
	{
		fd = (int)duk_to_int(ctx, -2);									
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	// [obj][table][enum][FD][emitter][options]
		if (Duktape_GetBooleanProperty(ctx, -1, "readset", 0)) { FD_SET(fd, readset); }
		if (Duktape_GetBooleanProperty(ctx, -1, "writeset", 0)) { FD_SET(fd, writeset); }
		if (Duktape_GetBooleanProperty(ctx, -1, "errorset", 0)) { FD_SET(fd, errorset); }
		duk_pop_3(ctx);														// [obj][table][enum]
	}

	duk_set_top(ctx, i);
}
void ILibDuktape_DescriptorEvents_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL) { return; }

	int i = duk_get_top(ctx);
	int fd;

	duk_push_array(ctx);												// [array]
	duk_push_heapptr(ctx, h);											// [array][obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [array][obj][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);					// [array][obj][table][enum]
	while (duk_next(ctx, -1, 1))										// [array][obj][table][enum][FD][emitter]
	{
		fd = (int)duk_to_int(ctx, -2);
		if (FD_ISSET(fd, readset) || FD_ISSET(fd, writeset) || FD_ISSET(fd, errorset))
		{
			duk_put_prop_index(ctx, -6, (duk_uarridx_t)duk_get_length(ctx, -6));		// [array][obj][table][enum][FD]
			duk_pop(ctx);												// [array][obj][table][enum]
		}
		else
		{
			duk_pop_2(ctx);												// [array][obj][table][enum]

		}
	}
	duk_pop_3(ctx);																						// [array]

	while (duk_get_length(ctx, -1) > 0)
	{
		duk_get_prop_string(ctx, -1, "pop");															// [array][pop]
		duk_dup(ctx, -2);																				// [array][pop][this]
		if (duk_pcall_method(ctx, 0) == 0)																// [array][emitter]
		{
			if ((fd = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_DescriptorEvents_FD, -1)) != -1)
			{
				if (FD_ISSET(fd, readset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "readset");		// [array][emitter][emit][this][readset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][readset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
				if (FD_ISSET(fd, writeset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "writeset");		// [array][emitter][emit][this][writeset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][writeset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
				if (FD_ISSET(fd, errorset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "errorset");		// [array][emitter][emit][this][errorset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][errorset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
			}
		}
		duk_pop(ctx);																					// [array]
	}
	duk_set_top(ctx, i);
}
duk_ret_t ILibDuktape_DescriptorEvents_Remove(duk_context *ctx)
{
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
	{
		// Windows Wait Handle
		HANDLE h = (HANDLE)Duktape_GetPointerProperty(ctx, 0, "_ptr");
		duk_push_this(ctx);													// [obj]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);	// [obj][table]
		ILibChain_RemoveWaitHandle(duk_ctx_chain(ctx), h);
		duk_push_sprintf(ctx, "%p", h);	duk_del_prop(ctx, -2);				// [obj][table]
		if (Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);
		}
		return(0);
	}
#endif
	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	if (!duk_is_null_or_undefined(ctx, 1) && duk_is_object(ctx, 1))
	{
		duk_get_prop(ctx, -2);											// [obj][table][value]
		if (duk_is_null_or_undefined(ctx, -1)) { return(0); }
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	//..[table][value][options]
		if (duk_has_prop_string(ctx, 1, "readset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "readset"); }
		if (duk_has_prop_string(ctx, 1, "writeset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "writeset"); }
		if (duk_has_prop_string(ctx, 1, "errorset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "errorset"); }
		if(	Duktape_GetBooleanProperty(ctx, -1, "readset", 0)	== 0 && 
			Duktape_GetBooleanProperty(ctx, -1, "writeset", 0)	== 0 &&
			Duktape_GetBooleanProperty(ctx, -1, "errorset", 0)	== 0)
		{
			// No FD_SET watchers, so we can remove the entire object
			duk_pop_2(ctx);												// [obj][table]
			duk_dup(ctx, 0);											// [obj][table][key]
			duk_del_prop(ctx, -2);										// [obj][table]
		}
	}
	else
	{
		// Remove All FD_SET watchers for this FD
		duk_del_prop(ctx, -2);											// [obj][table]
	}
	return(0);
}
#ifdef WIN32
char *DescriptorEvents_Status[] = { "NONE", "INVALID_HANDLE", "TIMEOUT", "REMOVED", "EXITING", "ERROR" }; 
BOOL ILibDuktape_DescriptorEvents_WaitHandleSink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, void* user)
{
	BOOL ret = FALSE;
	duk_context *ctx = (duk_context*)((void**)user)[0];

	int top = duk_get_top(ctx);
	duk_push_heapptr(ctx, ((void**)user)[1]);								// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [events][table]
	duk_push_sprintf(ctx, "%p", h);											// [events][table][key]
	duk_get_prop(ctx, -2);													// [events][table][val]
	if (!duk_is_null_or_undefined(ctx, -1))
	{
		void *hptr = duk_get_heapptr(ctx, -1);
		if (status != ILibWaitHandle_ErrorStatus_NONE) { duk_push_sprintf(ctx, "%p", h); duk_del_prop(ctx, -3); }
		duk_push_pointer(ctx, h); duk_put_prop_string(ctx, -3, ILibDuktape_DescriptorEvents_CURRENT);
		ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "signaled");			// [events][table][val][emit][this][signaled]
		duk_push_string(ctx, DescriptorEvents_Status[(int)status]);			// [events][table][val][emit][this][signaled][status]
		if (duk_pcall_method(ctx, 2) == 0)									// [events][table][val][undef]
		{
			ILibDuktape_EventEmitter_GetEmitReturn(ctx, hptr, "signaled");	// [events][table][val][undef][ret]
			if (duk_is_boolean(ctx, -1) && duk_get_boolean(ctx, -1) != 0)
			{
				ret = TRUE;
			}
		}	
		else
		{
			ILibDuktape_Process_UncaughtExceptionEx(ctx, "DescriptorEvents.signaled() threw an exception that will result in descriptor getting removed: ");
		}
		duk_set_top(ctx, top);
		duk_push_heapptr(ctx, ((void**)user)[1]);							// [events]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);	// [events][table]

		if (ret == FALSE && Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
		{
			//
			// We need to unhook the events to the descriptor event object, before we remove it from the table
			//
			duk_push_sprintf(ctx, "%p", h);									// [events][table][key]
			duk_get_prop(ctx, -2);											// [events][table][descriptorevent]
			duk_get_prop_string(ctx, -1, "removeAllListeners");				// [events][table][descriptorevent][remove]
			duk_swap_top(ctx, -2);											// [events][table][remove][this]
			duk_push_string(ctx, "signaled");								// [events][table][remove][this][signaled]
			duk_pcall_method(ctx, 1); duk_pop(ctx);							// [events][table]
			duk_push_sprintf(ctx, "%p", h);									// [events][table][key]
			duk_del_prop(ctx, -2);											// [events][table]
		}
		duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);	// [events][table]
	}
	duk_set_top(ctx, top);

	return(ret);
}
#endif
duk_ret_t ILibDuktape_DescriptorEvents_Add(duk_context *ctx)
{
	ILibDuktape_EventEmitter *e;
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
	{
		// Adding a Windows Wait Handle
		HANDLE h = (HANDLE)Duktape_GetPointerProperty(ctx, 0, "_ptr");
		if (h != NULL)
		{
			// Normal Add Wait Handle
			char *metadata = "DescriptorEvents";
			int timeout = -1;
			duk_push_this(ctx);														// [events]
			ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_ChainLink);
			duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [events][table]
			if (Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
			{
				// We are adding a wait handle from the event handler for this same signal, so remove this attribute,
				// so the signaler doesn't remove the object we are about to put in.
				duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);
			}
			duk_push_object(ctx);													// [events][table][value]
			duk_push_sprintf(ctx, "%p", h);											// [events][table][value][key]
			duk_dup(ctx, -2);														// [events][table][value][key][value]
			duk_dup(ctx, 0);
			duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_WaitHandle);	// [events][table][value][key][value]
			if (duk_is_object(ctx, 1)) { duk_dup(ctx, 1); }
			else { duk_push_object(ctx); }											// [events][table][value][key][value][options]
			if (duk_has_prop_string(ctx, -1, "metadata"))
			{
				duk_push_string(ctx, "DescriptorEvents, ");							// [events][table][value][key][value][options][str1]
				duk_get_prop_string(ctx, -2, "metadata");							// [events][table][value][key][value][options][str1][str2]
				duk_string_concat(ctx, -2);											// [events][table][value][key][value][options][str1][newstr]
				duk_remove(ctx, -2);												// [events][table][value][key][value][options][newstr]
				metadata = (char*)duk_get_string(ctx, -1);
				duk_put_prop_string(ctx, -2, "metadata");							// [events][table][value][key][value][options]
			}
			timeout = Duktape_GetIntPropertyValue(ctx, -1, "timeout", -1);
			duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);		// [events][table][value][key][value]
			duk_put_prop(ctx, -4);													// [events][table][value]
			e = ILibDuktape_EventEmitter_Create(ctx);
			ILibDuktape_EventEmitter_CreateEventEx(e, "signaled");
			ILibChain_AddWaitHandleEx(duk_ctx_chain(ctx), h, timeout, ILibDuktape_DescriptorEvents_WaitHandleSink, link->ExtraMemoryPtr, metadata);
			return(1);
		}
		return(ILibDuktape_Error(ctx, "Invalid Parameter"));
	}
#endif

	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	if (duk_has_prop(ctx, -2))											// [obj][table]
	{
		// There's already a watcher, so let's just merge the FD_SETS
		duk_dup(ctx, 0);												// [obj][table][key]
		duk_get_prop(ctx, -2);											// [obj][table][value]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	//..[table][value][options]
		if (Duktape_GetBooleanProperty(ctx, 1, "readset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "readset"); }
		if (Duktape_GetBooleanProperty(ctx, 1, "writeset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "writeset"); }
		if (Duktape_GetBooleanProperty(ctx, 1, "errorset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "errorset"); }
		duk_pop(ctx);													// [obj][table][value]
		return(1);
	}

	duk_push_object(ctx);												// [obj][table][value]
	duk_dup(ctx, 0);													// [obj][table][value][key]
	duk_dup(ctx, -2);													// [obj][table][value][key][value]
	e = ILibDuktape_EventEmitter_Create(ctx);	
	ILibDuktape_EventEmitter_CreateEventEx(e, "readset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "writeset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "errorset");
	duk_dup(ctx, 0);													// [obj][table][value][key][value][FD]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_FD);		// [obj][table][value][key][value]
	duk_dup(ctx, 1);													// [obj][table][value][key][value][options]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);	// [obj][table][value][key][value]
	char* metadata = Duktape_GetStringPropertyValue(ctx, -1, "metadata", NULL);
	if (metadata != NULL)
	{
		duk_push_string(ctx, "DescriptorEvents, ");						// [obj][table][value][key][value][str1]
		duk_push_string(ctx, metadata);									// [obj][table][value][key][value][str1][str2]
		duk_string_concat(ctx, -2);										// [obj][table][value][key][value][newStr]
		duk_put_prop_string(ctx, -2, "metadata");						// [obj][table][value][key][value]
	}
	duk_put_prop(ctx, -4);												// [obj][table][value]

	return(1);
}
duk_ret_t ILibDuktape_DescriptorEvents_Finalizer(duk_context *ctx)
{
	ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_DescriptorEvents_ChainLink);
	void *chain = Duktape_GetChain(ctx);

	link->PreSelectHandler = NULL;
	link->PostSelectHandler = NULL;
	((void**)link->ExtraMemoryPtr)[0] = NULL;
	((void**)link->ExtraMemoryPtr)[1] = NULL;
	
	if (ILibIsChainBeingDestroyed(chain) == 0)
	{
		ILibChain_SafeRemove(chain, link);
	}

	return(0);
}

#ifndef WIN32
void ILibDuktape_DescriptorEvents_GetCount_results_final(void *chain, void *user)
{
	duk_context *ctx = (duk_context*)((void**)user)[0];
	void *hptr = ((void**)user)[1];
	duk_push_heapptr(ctx, hptr);											// [promise]
	duk_get_prop_string(ctx, -1, "_RES");									// [promise][res]
	duk_swap_top(ctx, -2);													// [res][this]
	duk_push_int(ctx, ILibChain_GetDescriptorCount(duk_ctx_chain(ctx)));	// [res][this][count]
	duk_pcall_method(ctx, 1); duk_pop(ctx);									// ...
	free(user);
}
void ILibDuktape_DescriptorEvents_GetCount_results(void *chain, void *user)
{
	ILibChain_RunOnMicrostackThreadEx2(chain, ILibDuktape_DescriptorEvents_GetCount_results_final, user, 1);
}
#endif
duk_ret_t ILibDuktape_DescriptorEvents_GetCount_promise(duk_context *ctx)
{
	duk_push_this(ctx);		// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_DescriptorEvents_GetCount(duk_context *ctx)
{
	duk_eval_string(ctx, "require('promise');");								// [promise]
	duk_push_c_function(ctx, ILibDuktape_DescriptorEvents_GetCount_promise, 2);	// [promise][func]
	duk_new(ctx, 1);															// [promise]
	
#ifdef WIN32
	duk_get_prop_string(ctx, -1, "_RES");										// [promise][res]
	duk_dup(ctx, -2);															// [promise][res][this]
	duk_push_int(ctx, ILibChain_GetDescriptorCount(duk_ctx_chain(ctx)));		// [promise][res][this][count]
	duk_call_method(ctx, 1); duk_pop(ctx);										// [promise]
#else
	void **data = (void**)ILibMemory_Allocate(2 * sizeof(void*), 0, NULL, NULL);
	data[0] = ctx;
	data[1] = duk_get_heapptr(ctx, -1);
	ILibChain_InitDescriptorCount(duk_ctx_chain(ctx));
	ILibChain_RunOnMicrostackThreadEx2(duk_ctx_chain(ctx), ILibDuktape_DescriptorEvents_GetCount_results, data, 1);
#endif
	return(1);
}
char* ILibDuktape_DescriptorEvents_Query(void* chain, void *object, int fd, size_t *dataLen)
{
	char *retVal = ((ILibChain_Link*)object)->MetaData;
	*dataLen = strnlen_s(retVal, 1024);

	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL || !duk_ctx_is_alive(ctx)) { return(retVal); }
	int top = duk_get_top(ctx);

	duk_push_heapptr(ctx, h);												// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);		// [events][table]
	duk_push_int(ctx, fd);													// [events][table][key]
	if (duk_has_prop(ctx, -2) != 0)											// [events][table]
	{
		duk_push_int(ctx, fd); duk_get_prop(ctx, -2);						// [events][table][val]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	// [events][table][val][options]
		if (!duk_is_null_or_undefined(ctx, -1))
		{
			retVal = Duktape_GetStringPropertyValueEx(ctx, -1, "metadata", retVal, dataLen);
		}
	}

	duk_set_top(ctx, top);
	return(retVal);
}
duk_ret_t ILibDuktape_DescriptorEvents_descriptorAdded(duk_context *ctx)
{
	duk_push_this(ctx);																// [DescriptorEvents]
	if (duk_is_number(ctx, 0))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);			// [DescriptorEvents][table]
		duk_dup(ctx, 0);															// [DescriptorEvents][table][key]
	}
	else
	{
		if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [DescriptorEvents][table]	
			duk_push_sprintf(ctx, "%p", Duktape_GetPointerProperty(ctx, 0, "_ptr"));// [DescriptorEvents][table][key]
		}
		else
		{
			return(ILibDuktape_Error(ctx, "Invalid Argument. Must be a descriptor or HANDLE"));
		}
	}
	duk_push_boolean(ctx, duk_has_prop(ctx, -2));
	return(1);
}
void ILibDuktape_DescriptorEvents_Push(duk_context *ctx, void *chain)
{
	ILibChain_Link *link = (ILibChain_Link*)ILibChain_Link_Allocate(sizeof(ILibChain_Link), 2 * sizeof(void*));
	link->MetaData = "DescriptorEvents";
	link->PreSelectHandler = ILibDuktape_DescriptorEvents_PreSelect;
	link->PostSelectHandler = ILibDuktape_DescriptorEvents_PostSelect;
	link->QueryHandler = ILibDuktape_DescriptorEvents_Query;

	duk_push_object(ctx);
	duk_push_pointer(ctx, link); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_ChainLink);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Table);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_HTable);
	
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DescriptorEvents_Finalizer);

	((void**)link->ExtraMemoryPtr)[0] = ctx;
	((void**)link->ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_CreateInstanceMethod(ctx, "addDescriptor", ILibDuktape_DescriptorEvents_Add, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeDescriptor", ILibDuktape_DescriptorEvents_Remove, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getDescriptorCount", ILibDuktape_DescriptorEvents_GetCount, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "descriptorAdded", ILibDuktape_DescriptorEvents_descriptorAdded, 1);

	ILibAddToChain(chain, link);
}
duk_ret_t ILibDuktape_Polyfills_filehash(duk_context *ctx)
{
	char *hash = duk_push_fixed_buffer(ctx, UTIL_SHA384_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA384_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);
	if (GenerateSHA384FileHash((char*)duk_require_string(ctx, 0), hash) == 0)
	{
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Error generating FileHash "));
	}
}

duk_ret_t ILibDuktape_Polyfills_ipv4From(duk_context *ctx)
{
	int v = duk_require_int(ctx, 0);
	ILibDuktape_IPV4AddressToOptions(ctx, v);
	duk_get_prop_string(ctx, -1, "host");
	return(1);
}

duk_ret_t ILibDuktape_Polyfills_global(duk_context *ctx)
{
	duk_push_global_object(ctx);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_isBuffer(duk_context *ctx)
{
	duk_push_boolean(ctx, duk_is_buffer_data(ctx, 0));
	return(1);
}
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
duk_ret_t ILibDuktape_ioctl_func(duk_context *ctx)
{
	int fd = (int)duk_require_int(ctx, 0);
	int code = (int)duk_require_int(ctx, 1);
	duk_size_t outBufferLen = 0;
	char *outBuffer = Duktape_GetBuffer(ctx, 2, &outBufferLen);

	duk_push_int(ctx, ioctl(fd, _IOC(_IOC_READ | _IOC_WRITE, 'H', code, outBufferLen), outBuffer) ? errno : 0);
	return(1);
}
void ILibDuktape_ioctl_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_ioctl_func, DUK_VARARGS);
	ILibDuktape_WriteID(ctx, "ioctl");
}
#endif
void ILibDuktape_uuidv4_Push(duk_context *ctx, void *chain)
{	
	duk_push_object(ctx);
	char uuid[] = "module.exports = function uuidv4()\
						{\
							var b = Buffer.alloc(16);\
							b.randomFill();\
							var v = b.readUInt16BE(6) & 0xF1F;\
							v |= (4 << 12);\
							v |= (4 << 5);\
							b.writeUInt16BE(v, 6);\
							var ret = b.slice(0, 4).toString('hex') + '-' + b.slice(4, 6).toString('hex') + '-' + b.slice(6, 8).toString('hex') + '-' + b.slice(8, 10).toString('hex') + '-' + b.slice(10).toString('hex');\
							ret = '{' + ret.toLowerCase() + '}';\
							return (ret);\
						};";

	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, uuid, sizeof(uuid) - 1);
}

duk_ret_t ILibDuktape_Polyfills_debugHang(duk_context *ctx)
{
	int val = duk_get_top(ctx) == 0 ? 30000 : duk_require_int(ctx, 0);

#ifdef WIN32
	Sleep(val);
#else
	sleep(val);
#endif

	return(0);
}

extern void checkForEmbeddedMSH_ex2(char *binPath, char **eMSH);
duk_ret_t ILibDuktape_Polyfills_MSH(duk_context *ctx)
{
	duk_eval_string(ctx, "process.execPath");	// [string]
	char *exepath = (char*)duk_get_string(ctx, -1);
	char *msh;
	duk_size_t s = 0;

	checkForEmbeddedMSH_ex2(exepath, &msh);
	if (msh == NULL)
	{
		duk_eval_string(ctx, "require('fs')");			// [fs]
		duk_get_prop_string(ctx, -1, "readFileSync");	// [fs][readFileSync]
		duk_swap_top(ctx, -2);							// [readFileSync][this]
#ifdef _POSIX
		duk_push_sprintf(ctx, "%s.msh", exepath);		// [readFileSync][this][path]
#else
		duk_push_string(ctx, exepath);					// [readFileSync][this][path]
		duk_string_split(ctx, -1, ".exe");				// [readFileSync][this][path][array]
		duk_remove(ctx, -2);							// [readFileSync][this][array]
		duk_array_join(ctx, -1, ".msh");				// [readFileSync][this][array][path]
		duk_remove(ctx, -2);							// [readFileSync][this][path]
#endif
		duk_push_object(ctx);							// [readFileSync][this][path][options]
		duk_push_string(ctx, "rb"); duk_put_prop_string(ctx, -2, "flags");
		if (duk_pcall_method(ctx, 2) == 0)				// [buffer]
		{
			msh = Duktape_GetBuffer(ctx, -1, &s);
		}
	}

	duk_push_object(ctx);														// [obj]
	if (msh != NULL)
	{
		if (s == 0) { s = ILibMemory_Size(msh); }
		parser_result *pr = ILibParseString(msh, 0, s, "\n", 1);
		parser_result_field *f = pr->FirstResult;
		int i;
		while (f != NULL)
		{
			if (f->datalength > 0)
			{
				i = ILibString_IndexOf(f->data, f->datalength, "=", 1);
				if (i >= 0)
				{
					duk_push_lstring(ctx, f->data, (duk_size_t)i);						// [obj][key]
					if (f->data[f->datalength - 1] == '\r')
					{
						duk_push_lstring(ctx, f->data + i + 1, f->datalength - i - 2);	// [obj][key][value]
					}
					else
					{
						duk_push_lstring(ctx, f->data + i + 1, f->datalength - i - 1);	// [obj][key][value]
					}
					duk_put_prop(ctx, -3);												// [obj]
				}
			}
			f = f->NextResult;
		}
		ILibDestructParserResults(pr);
		ILibMemory_Free(msh);
	}																					// [msh]

	if (duk_peval_string(ctx, "require('MeshAgent').getStartupOptions()") == 0)			// [msh][obj]
	{
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);								// [msh][obj][enum]
		while (duk_next(ctx, -1, 1))													// [msh][obj][enum][key][val]
		{
			if (duk_has_prop_string(ctx, -5, duk_get_string(ctx, -2)) == 0)
			{
				duk_put_prop(ctx, -5);													// [msh][obj][enum]
			}
			else
			{
				duk_pop_2(ctx);															// [msh][obj][enum]
			}
		}
		duk_pop(ctx);																	// [msh][obj]
	}
	duk_pop(ctx);																		// [msh]
	return(1);
}
#if defined(ILIBMEMTRACK) && !defined(ILIBCHAIN_GLOBAL_LOCK)
extern size_t ILib_NativeAllocSize;
extern ILibSpinLock ILib_MemoryTrackLock;
duk_ret_t ILibDuktape_Polyfills_NativeAllocSize(duk_context *ctx)
{
	ILibSpinLock_Lock(&ILib_MemoryTrackLock);
	duk_push_uint(ctx, ILib_NativeAllocSize);
	ILibSpinLock_UnLock(&ILib_MemoryTrackLock);
	return(1);
}
#endif
duk_ret_t ILibDuktape_Polyfills_WeakReference_isAlive(duk_context *ctx)
{
	duk_push_this(ctx);								// [weak]
	void **p = Duktape_GetPointerProperty(ctx, -1, "\xFF_heapptr");
	duk_push_boolean(ctx, ILibMemory_CanaryOK(p));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_WeakReference_object(duk_context *ctx)
{
	duk_push_this(ctx);								// [weak]
	void **p = Duktape_GetPointerProperty(ctx, -1, "\xFF_heapptr");
	if (ILibMemory_CanaryOK(p))
	{
		duk_push_heapptr(ctx, p[0]);
	}
	else
	{
		duk_push_null(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_WeakReference(duk_context *ctx)
{
	duk_push_object(ctx);														// [weak]
	ILibDuktape_WriteID(ctx, "WeakReference");		
	duk_dup(ctx, 0);															// [weak][obj]
	void *j = duk_get_heapptr(ctx, -1);
	void **p = (void**)Duktape_PushBuffer(ctx, sizeof(void*));					// [weak][obj][buffer]
	p[0] = j;
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));// [weak][obj]

	duk_pop(ctx);																// [weak]

	duk_push_pointer(ctx, p); duk_put_prop_string(ctx, -2, "\xFF_heapptr");		// [weak]
	ILibDuktape_CreateInstanceMethod(ctx, "isAlive", ILibDuktape_Polyfills_WeakReference_isAlive, 0);
	ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "object", ILibDuktape_Polyfills_WeakReference_object, 1);
	return(1);
}

duk_ret_t ILibDuktape_Polyfills_rootObject(duk_context *ctx)
{
	void *h = _duk_get_first_object(ctx);
	duk_push_heapptr(ctx, h);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_nextObject(duk_context *ctx)
{
	void *h = duk_require_heapptr(ctx, 0);
	void *next = _duk_get_next_object(ctx, h);
	if (next != NULL)
	{
		duk_push_heapptr(ctx, next);
	}
	else
	{
		duk_push_null(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_countObject(duk_context *ctx)
{
	void *h = _duk_get_first_object(ctx);
	duk_int_t i = 1;

	while (h != NULL)
	{
		if ((h = _duk_get_next_object(ctx, h)) != NULL) { ++i; }
	}
	duk_push_int(ctx, i);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_hide(duk_context *ctx)
{
	duk_idx_t top = duk_get_top(ctx);
	duk_push_heap_stash(ctx);									// [stash]

	if (top == 0)
	{
		duk_get_prop_string(ctx, -1, "__STASH__");				// [stash][value]
	}
	else
	{
		if (duk_is_boolean(ctx, 0))
		{
			duk_get_prop_string(ctx, -1, "__STASH__");			// [stash][value]
			if (duk_require_boolean(ctx, 0))
			{
				duk_del_prop_string(ctx, -2, "__STASH__");
			}
		}
		else
		{
			duk_dup(ctx, 0);									// [stash][value]
			duk_dup(ctx, -1);									// [stash][value][value]
			duk_put_prop_string(ctx, -3, "__STASH__");			// [stash][value]
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_altrequire(duk_context *ctx)
{
	duk_size_t idLen;
	char *id = (char*)duk_get_lstring(ctx, 0, &idLen);

	duk_push_heap_stash(ctx);										// [stash]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_AltRequireTable))
	{
		duk_push_object(ctx); 
		duk_put_prop_string(ctx, -2, ILibDuktape_AltRequireTable);
	}
	duk_get_prop_string(ctx, -1, ILibDuktape_AltRequireTable);		// [stash][table]

	if (ILibDuktape_ModSearch_IsRequired(ctx, id, idLen) == 0)
	{
		// Module was not 'require'ed yet
		duk_push_sprintf(ctx, "global._legacyrequire('%s');", id);	// [stash][table][str]
		duk_eval(ctx);												// [stash][table][value]
		duk_dup(ctx, -1);											// [stash][table][value][value]
		duk_put_prop_string(ctx, -3, id);							// [stash][table][value]
	}
	else
	{
		// Module was already required, so we need to do some additional checks
		if (duk_has_prop_string(ctx, -1, id)) // Check to see if there is a new instance we can use
		{
			duk_get_prop_string(ctx, -1, id);							// [stash][table][value]
		}
		else
		{
			// There is not an instance here, so we need to instantiate a new alt instance
			duk_push_sprintf(ctx, "getJSModule('%s');", id);			// [stash][table][str]
			if (duk_peval(ctx) != 0)									// [stash][table][js]
			{
				// This was a native module, so just return it directly
				duk_push_sprintf(ctx, "global._legacyrequire('%s');", id);	
				duk_eval(ctx);												
				return(1);
			}
			duk_eval_string(ctx, "global._legacyrequire('uuid/v4')();");				// [stash][table][js][uuid]
			duk_push_sprintf(ctx, "%s_%s", id, duk_get_string(ctx, -1));// [stash][table][js][uuid][newkey]

			duk_push_global_object(ctx);				// [stash][table][js][uuid][newkey][g]
			duk_get_prop_string(ctx, -1, "addModule");	// [stash][table][js][uuid][newkey][g][addmodule]
			duk_remove(ctx, -2);						// [stash][table][js][uuid][newkey][addmodule]
			duk_dup(ctx, -2);							// [stash][table][js][uuid][newkey][addmodule][key]
			duk_dup(ctx, -5);							// [stash][table][js][uuid][newkey][addmodule][key][module]
			duk_call(ctx, 2);							// [stash][table][js][uuid][newkey][ret]
			duk_pop(ctx);								// [stash][table][js][uuid][newkey]
			duk_push_sprintf(ctx, "global._legacyrequire('%s');", duk_get_string(ctx, -1));
			duk_eval(ctx);								// [stash][table][js][uuid][newkey][newval]
			duk_dup(ctx, -1);							// [stash][table][js][uuid][newkey][newval][newval]
			duk_put_prop_string(ctx, -6, id);			// [stash][table][js][uuid][newkey][newval]
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_resolve(duk_context *ctx)
{
	char tmp[512];
	char *host = (char*)duk_require_string(ctx, 0);
	struct sockaddr_in6 addr[16];
	memset(&addr, 0, sizeof(addr));

	int i, count = ILibResolveEx2(host, 443, addr, 16);
	duk_push_array(ctx);															// [ret]
	duk_push_array(ctx);															// [ret][integers]

	for (i = 0; i < count; ++i)
	{
		if (ILibInet_ntop2((struct sockaddr*)(&addr[i]), tmp, sizeof(tmp)) != NULL)
		{
			duk_push_string(ctx, tmp);												// [ret][integers][string]
			duk_array_push(ctx, -3);												// [ret][integers]

			duk_push_int(ctx, ((struct sockaddr_in*)&addr[i])->sin_addr.s_addr);	// [ret][integers][value]
			duk_array_push(ctx, -2);												// [ret][integers]
		}
	}
	ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "_integers", 0);			// [ret]
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_getModules(duk_context *ctx)
{
	char *id;
	duk_idx_t top;
	duk_push_heap_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");						// [stash][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);					// [stash][table][enum]
	duk_push_array(ctx);												// [stash][table][enum][array]
	top = duk_get_top(ctx);
	while (duk_next(ctx, -2, 0))										// [stash][table][enum][array][key]
	{
		id = (char*)duk_to_string(ctx, -1);
		if (ModSearchTable_Get(ctx, -4, "\xFF_Modules_File", id) > 0)	// [stash][table][enum][array][key][value]
		{	
			duk_pop(ctx);												// [stash][table][enum][array][key]
			duk_array_push(ctx, -2);									// [stash][table][enum][array]
		}
		duk_set_top(ctx, top);
	}
	return(1);
}
void ILibDuktape_Polyfills_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "queue", ILibDuktape_Queue_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "DynamicBuffer", ILibDuktape_DynamicBuffer_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "stream", ILibDuktape_Stream_Init);
	ILibDuktape_ModSearch_AddHandler(ctx, "http-headers", ILibDuktape_httpHeaders_PUSH);

#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "pkcs7", ILibDuktape_PKCS7_Push);
#endif

#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "bignum", ILibDuktape_bignum_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "dataGenerator", ILibDuktape_dataGenerator_Push);
#endif
	ILibDuktape_ModSearch_AddHandler(ctx, "ChainViewer", ILibDuktape_ChainViewer_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "DescriptorEvents", ILibDuktape_DescriptorEvents_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "uuid/v4", ILibDuktape_uuidv4_Push);
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	ILibDuktape_ModSearch_AddHandler(ctx, "ioctl", ILibDuktape_ioctl_Push);
#endif


	// Global Polyfills
	duk_push_global_object(ctx);													// [g]
	ILibDuktape_WriteID(ctx, "Global");
	ILibDuktape_Polyfills_Array(ctx);
	ILibDuktape_Polyfills_String(ctx);
	ILibDuktape_Polyfills_Buffer(ctx);
	ILibDuktape_Polyfills_Console(ctx);
	ILibDuktape_Polyfills_byte_ordering(ctx);
	ILibDuktape_Polyfills_timer(ctx);
	ILibDuktape_Polyfills_object(ctx);
	ILibDuktape_Polyfills_function(ctx);
	
	ILibDuktape_CreateInstanceMethod(ctx, "addModuleObject", ILibDuktape_Polyfills_addModuleObject, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addModule", ILibDuktape_Polyfills_addModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "addCompressedModule", ILibDuktape_Polyfills_addCompressedModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getModules", ILibDuktape_Polyfills_getModules, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModule", ILibDuktape_Polyfills_getJSModule, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModuleDate", ILibDuktape_Polyfills_getJSModuleDate, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugHang", ILibDuktape_Polyfills_debugHang, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugCrash", ILibDuktape_Polyfills_debugCrash, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugGC", ILibDuktape_Polyfills_debugGC, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debug", ILibDuktape_Polyfills_debug, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getSHA384FileHash", ILibDuktape_Polyfills_filehash, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_ipv4From", ILibDuktape_Polyfills_ipv4From, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_isBuffer", ILibDuktape_Polyfills_isBuffer, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_MSH", ILibDuktape_Polyfills_MSH, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "WeakReference", ILibDuktape_Polyfills_WeakReference, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_rootObject", ILibDuktape_Polyfills_rootObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_nextObject", ILibDuktape_Polyfills_nextObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_countObjects", ILibDuktape_Polyfills_countObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_hide", ILibDuktape_Polyfills_hide, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_altrequire", ILibDuktape_Polyfills_altrequire, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "resolve", ILibDuktape_Polyfills_resolve, 1);

#if defined(ILIBMEMTRACK) && !defined(ILIBCHAIN_GLOBAL_LOCK)
	ILibDuktape_CreateInstanceMethod(ctx, "_NativeAllocSize", ILibDuktape_Polyfills_NativeAllocSize, 0);
#endif

#ifndef MICROSTACK_NOTLS
	ILibDuktape_CreateInstanceMethod(ctx, "crc32c", ILibDuktape_Polyfills_crc32c, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "crc32", ILibDuktape_Polyfills_crc32, DUK_VARARGS);
#endif
	ILibDuktape_CreateEventWithGetter(ctx, "global", ILibDuktape_Polyfills_global);
	duk_pop(ctx);																	// ...

	ILibDuktape_Debugger_Init(ctx, 9091);
}

#ifdef __DOXY__
/*!
\brief String 
*/
class String
{
public:
	/*!
	\brief Finds a String within another String
	\param str \<String\> Substring to search for
	\return <Integer> Index of where the string was found. -1 if not found
	*/
	Integer indexOf(str);
	/*!
	\brief Extracts a String from a String.
	\param startIndex <Integer> Starting index to extract
	\param length <Integer> Number of characters to extract
	\return \<String\> extracted String
	*/
	String substr(startIndex, length);
	/*!
	\brief Extracts a String from a String.
	\param startIndex <Integer> Starting index to extract
	\param endIndex <Integer> Ending index to extract
	\return \<String\> extracted String
	*/
	String splice(startIndex, endIndex);
	/*!
	\brief Split String into substrings
	\param str \<String\> Delimiter to split on
	\return Array of Tokens
	*/
	Array<String> split(str);
	/*!
	\brief Determines if a String starts with the given substring
	\param str \<String\> substring 
	\return <boolean> True, if this String starts with the given substring
	*/
	boolean startsWith(str);
};
/*!
\brief Instances of the Buffer class are similar to arrays of integers but correspond to fixed-sized, raw memory allocations.
*/
class Buffer
{
public:
	/*!
	\brief Create a new Buffer instance of the specified number of bytes
	\param size <integer> 
	\return \<Buffer\> new Buffer instance
	*/
	Buffer(size);

	/*!
	\brief Returns the amount of memory allocated in  bytes
	*/
	integer length;
	/*!
	\brief Creates a new Buffer instance from an encoded String
	\param str \<String\> encoded String
	\param encoding \<String\> Encoding. Can be either 'base64' or 'hex'
	\return \<Buffer\> new Buffer instance
	*/
	static Buffer from(str, encoding);
	/*!
	\brief Decodes Buffer to a String
	\param encoding \<String\> Optional. Can be either 'base64' or 'hex'. If not specified, will just encode as an ANSI string
	\param start <integer> Optional. Starting offset. <b>Default:</b> 0
	\param end <integer> Optional. Ending offset (not inclusive) <b>Default:</b> buffer length
	\return \<String\> Encoded String
	*/
	String toString([encoding[, start[, end]]]);
	/*!
	\brief Returns a new Buffer that references the same memory as the original, but offset and cropped by the start and end indices.
	\param start <integer> Where the new Buffer will start. <b>Default:</b> 0
	\param end <integer> Where the new Buffer will end. (Not inclusive) <b>Default:</b> buffer length
	\return \<Buffer\> 
	*/
	Buffer slice([start[, end]]);
};
/*!
\brief Console
*/
class Console
{
public:
	/*!
	\brief Serializes the input parameters to the Console Display
	\param args <any>
	*/
	void log(...args);
};
/*!
\brief Global Timer Methods
*/
class Timers
{
public:
	/*!
	\brief Schedules the "immediate" execution of the callback after I/O events' callbacks. 
	\param callback <func> Function to call at the end of the event loop
	\param args <any> Optional arguments to pass when the callback is called
	\return Immediate for use with clearImmediate().
	*/
	Immediate setImmediate(callback[, ...args]);
	/*!
	\brief Schedules execution of a one-time callback after delay milliseconds. 
	\param callback <func> Function to call when the timeout elapses
	\param args <any> Optional arguments to pass when the callback is called
	\return Timeout for use with clearTimeout().
	*/
	Timeout setTimeout(callback, delay[, ...args]);
	/*!
	\brief Schedules repeated execution of callback every delay milliseconds.
	\param callback <func> Function to call when the timer elapses
	\param args <any> Optional arguments to pass when the callback is called
	\return Timeout for use with clearInterval().
	*/
	Timeout setInterval(callback, delay[, ...args]);

	/*!
	\brief Cancels a Timeout returned by setTimeout()
	\param timeout Timeout
	*/
	void clearTimeout(timeout);
	/*!
	\brief Cancels a Timeout returned by setInterval()
	\param interval Timeout
	*/
	void clearInterval(interval);
	/*!
	\brief Cancels an Immediate returned by setImmediate()
	\param immediate Immediate
	*/
	void clearImmediate(immediate);

	/*!
	\brief Scheduled Timer
	*/
	class Timeout
	{
	public:
	};
	/*!
	\implements Timeout
	\brief Scheduled Immediate
	*/
	class Immediate
	{
	public:
	};
};

/*!
\brief Global methods for byte ordering manipulation
*/
class BytesOrdering
{
public:
	/*!
	\brief Converts 2 bytes from network order to host order
	\param buffer \<Buffer\> bytes to convert
	\param offset <integer> offset to start
	\return <integer> host order value
	*/
	static integer ntohs(buffer, offset);
	/*!
	\brief Converts 4 bytes from network order to host order
	\param buffer \<Buffer\> bytes to convert
	\param offset <integer> offset to start
	\return <integer> host order value
	*/
	static integer ntohl(buffer, offset);
	/*!
	\brief Writes 2 bytes in network order
	\param buffer \<Buffer\> Buffer to write to
	\param offset <integer> offset to start writing
	\param val <integer> host order value to write
	*/
	static void htons(buffer, offset, val);
	/*!
	\brief Writes 4 bytes in network order
	\param buffer \<Buffer\> Buffer to write to
	\param offset <integer> offset to start writing
	\param val <integer> host order value to write
	*/
	static void htonl(buffer, offset, val);
};
#endif
