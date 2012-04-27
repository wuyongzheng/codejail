libjpng.so: jpng.c
	gcc -shared -fPIC -Wall -Wl,-soname,libjpng.so -o libjpng.so jpng.c -I../lib -L../lib -lc -ldl -lcodejail

libjtiff.so: jtiff.c
	gcc -shared -fPIC -Wall -Wl,-soname,libjtiff.so -o libjtiff.so jtiff.c -I../lib -L../lib -lc -ldl -lcodejail

libjexpat.so: jexpat.c
	gcc -shared -fPIC -Wall -Wl,-soname,libjexpat.so -o libjexpat.so jexpat.c -I../lib -L../lib -lc -ldl -lcodejail
