#include <stdio.h>
//#include <iostream.h>
#include <pthread.h>
#include <assert.h> 
//#include <atomic>

int x=0,y=0, a=0;

void *thread1(void * threadid)
{
x=1; 
y=1; 
}

void *thread2(void * threadid)
{
int p;
y=2;
p=x;
if(p==0)
a=1;
}


int main()
{
  int i=0;
  int j=1;
  int rc1,rc2;
  pthread_t threads[2];
  rc1 = pthread_create(&threads[0], NULL,
                          thread1, (void *)i);
  rc2 = pthread_create(&threads[1], NULL, 
                          thread2, (void *)j);
  (void) pthread_join(threads[0], NULL);
  (void) pthread_join(threads[1], NULL);
  assert (!((y==2) && (a==1)));
}
