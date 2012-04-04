BEGIN {
	FS = "\t";
	print "#define _GNU_SOURCE";
	print "#include <stdio.h>";
	print "#include <assert.h>";
	print "#include <dlfcn.h>";
	print "#include <png.h>";
	print "";
	print "static __thread int calldepth = 0;";
	print "";
}

function implode (arr, sep,    str) {
	if (!(0 in arr))
		return "";
	str = arr[0];
	for (i = 1; i in arr; i ++)
		str = str sep arr[i];
	return str;
}

function line2arr (start, count, arr) {
	for (i in arr)
		delete arr[i]
	for (i = 0; i < count; i ++)
		arr[i] = $(start+i);
}

function getformat (type) {
	switch (type) {
		case /\*$/:
		case /p$/:
		case /_ptr$/:
		case "voidpf":
			return "%p";
		case "double":
		case "float":
			return "%f";
		case "int":
			return "%d";
		case "png_byte":
			return "%u";
		case "png_fixed_point":
		case "png_int_32":
		case "time_t":
			return "%ld";
		case "png_uint_16":
			return "%hu";
		case "png_uint_32":
			return "%lu";
		case "uInt":
		case "unsigned int":
			return "%u";
		case "png_size_t":
			return "%zd";
		default:
			return "\"opps!";
	}
}

{
	for (i in arrt)
		delete arrt[i];
	for (i in arrn)
		delete arrn[i];
	for (i in arrf)
		delete arrf[i];

	line2arr(3, NF-2, arra);
	for (i = 3; i <= NF; i ++) {
		name = gensub(/.*[\* ]/, "", "g", $i);
		type = substr($i, 0, length($i) - length(name));
		sub(" *$", "", type);
#		print "type:\t" type;
		arrt[i-3] = type;
		arrn[i-3] = name;
		arrf[i-3] = getformat(type);
	}

	printf("%s %s (%s)\n", $1, $2, implode(arra, ", "));
	print "{";
	printf("\tstatic %s (*realfunc) (%s) = NULL;\n", $1, implode(arrt, ", "));
	print "\tif (!realfunc)";
	printf("\t\trealfunc = (%s (*)(%s))dlsym(RTLD_NEXT, \"%s\");\n", $1, implode(arrt, ", "), $2);
	print "";
	print "\tcalldepth ++;";
	if ($1 == "void")
		printf("\trealfunc(%s);\n", implode(arrn, ", "));
	else
		printf("\t%s retval = realfunc(%s);\n", $1, implode(arrn, ", "));
	print "\tcalldepth --;";
	print "";
	print "\tassert(calldepth >= 0);";

#	print "\tif (calldepth == 0)";
#	if ($1 == "void") {
#		printf("\t\tfprintf(stderr, \"" $2 "(%s)\\n\"%s);\n",
#			implode(arrf, ", "),
#			NF == 2 ? "" : ", " implode(arrn, ", "));
#	} else {
#		printf("\t\tfprintf(stderr, \"" $2 "(%s) = %s\\n\"%s, retval);\n",
#			implode(arrf, ", "),
#			getformat($1),
#			NF == 2 ? "" : ", " implode(arrn, ", "));
#		print "\treturn retval;";
#	}

	if ($1 == "void") {
		printf("\tfprintf(stderr, \"%%d " $2 "(%s)\\n\", calldepth%s);\n",
			implode(arrf, ", "),
			NF == 2 ? "" : ", " implode(arrn, ", "));
	} else {
		printf("\tfprintf(stderr, \"%%d " $2 "(%s) = %s\\n\", calldepth%s, retval);\n",
			implode(arrf, ", "),
			getformat($1),
			NF == 2 ? "" : ", " implode(arrn, ", "));
		print "\treturn retval;";
	}

	print "}";
	print "";
}
