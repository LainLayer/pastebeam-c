# About

A C program to post and get shit from the epic project pastebeam https://github.com/tsoding/pastebeam

# Compile this shit

```console
gcc -o pastebeam pastebeam.c
```

## With optimizations

```
echo "some text" > test.txt
gcc -o pastebeam pastebeam.c -O3 -ffast-math -march=native -mtune=native -flto=auto -fprofile-generate
./pasteabeam post test.txt
gcc -o pastebeam pastebeam.c -O3 -ffast-math -march=native -mtune=native -flto=auto -fprofile-use
```

# Usage

```
get <id>        - get a pastebin from its id
post <filename> - post a file and print its id
```
