
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include <stdio.h>
//#include <iostream.h>
#include <assert.h>

char *v;

void *thread1(void * arg)
{
  v = malloc(sizeof(char) * 8);
  return 0;
}

void *thread2(void *arg)
{
  if (v) strcpy(v, "Bigshot");
  return 0;
}


int main()
{
  pthread_t t1, t2;

  pthread_create(&t1, 0, thread1, 0);
  pthread_join(t1, 0);

  pthread_create(&t2, 0, thread2, 0);
  pthread_join(t2, 0);

  assert(v[0] == 'B');  // <---- wrong, malloc() can fail and therefore no strcpy! Competition's rule: malloc() never fails, thus it is safe.

  return 0;
}

