/*
   These are the Random Number Generator tests suggested by the 
   FIPS 140-1 spec section 4.11.1 (http://csrc.nist.gov/fips/fips1401.htm)
   The Monobit, Poker, Runs, and Long Runs tests are implemented below.
*/
#define RNG_DEVICE "/dev/intel_rng"
#define RNG_LOOPS 25


#include <stdio.h>

FILE *dev;

char read_rng_byte() {
  char random;
  fscanf(dev,"%c",&random);
  return random;
}

int do_test() {

unsigned char rbyte = 0;
int poker[16],runs[12],i,j;
double pokertest;
int longrun = 0;
int current = 0;
int rlength = 0;
int ones = 0;

for(i=0; i<16; i++) {
  poker[i] = 0;
}

for(i=0; i<12; i++) {
  runs[i] = 0;
}

rlength = 999;
ones = 0;
for(i=0; i<2500; i++) {
  rbyte = read_rng_byte();

  //  printf("%d: %x\n",i,rbyte);

  ones += rbyte & 1;
  ones += (rbyte & 2)>>1;
  ones += (rbyte & 4)>>2;
  ones += (rbyte & 8)>>3;
  ones += (rbyte & 16)>>4;
  ones += (rbyte & 32)>>5;
  ones += (rbyte & 64)>>6;
  ones += (rbyte & 128)>>7;

  poker[rbyte>>4] += 1;
  poker[rbyte & 15] += 1;

  /* Trick to make sure current != the first bit so we don't screw
     up the first runlength */
  if(rlength == 999) {
    current = !((rbyte & 128)>>7);
    rlength = 1;
  }
  for(j=7; j>=0; j--) {
    //  printf("%d %d %d\n",rlength,current,((rbyte & 1<<j)>>j) );
    if(((rbyte & 1<<j)>>j) == current) {
      rlength++;

    }
    else {
      /* If runlength is 1-6 count it in correct bucket. 0's go in
	 runs[0-5] 1's go in runs[6-11] hence the 6*current below */
      if(rlength < 6) {
	runs[rlength - 1 + (6*current)]++;
      }
      if(rlength >= 6) {
	runs[5 + (6*current)]++;
      }
      /* Check if we just failed longrun test */
      if(rlength > longrun) {
	longrun = rlength;
      }
      rlength=1;
      /* flip the current run type */
      current = (rbyte & 1<<j)>>j;
    }
  }
}

/* add in the last (possibly incomplete) run */
if(rlength <= 6) {
  runs[rlength - 1 + (6*current)]++;
}
if(rlength > longrun) {
  longrun = rlength;
}

/* To poker test */
pokertest = 0;
for(i=0; i<16; i++) {
  //  printf("P%d:  %d\n",i,poker[i]);
  pokertest += (double)(poker[i] * poker[i]);
}
pokertest = (16.0/5000.0) * pokertest - 5000.0;

/* Data is all gathered, do the tests */
 printf("Ones: %d\nPokertest: %f\nRuns: %d %d %d %d %d %d\n      %d %d %d %d %d %d\nLong Run: %d\n\n",ones,(float)pokertest,runs[0],runs[1],runs[2],runs[3],runs[4],runs[5],runs[6],runs[7],runs[8],runs[9],runs[10],runs[11],longrun);


if(! ((ones < 10346) && (ones > 9654)) ){
  printf("  RNG failed Monobit test.\n");
  return 1;
}

if(! ((pokertest < 57.4) && (pokertest > 1.03)) ){
  printf("  RNG failed Poker test.\n");
  return 1;
}

if(! ((runs[0] >= 2267) && (runs[0] <= 2733) &&
      (runs[1] >= 1079) && (runs[1] <= 1421) &&
      (runs[2] >= 502)  && (runs[2] <= 748) &&
      (runs[3] >= 223)  && (runs[3] <= 402) &&
      (runs[4] >= 90)   && (runs[4] <= 223) &&
      (runs[5] >= 90)   && (runs[5] <= 223) &&
      (runs[6] >= 2267) && (runs[6] <= 2733) &&
      (runs[7] >= 1079) && (runs[7] <= 1421) &&
      (runs[8] >= 502)  && (runs[8] <= 748) &&
      (runs[9] >= 223)  && (runs[9] <= 402) &&
      (runs[10] >= 90)   && (runs[10] <= 223) &&
      (runs[11] >= 90)   && (runs[11] <= 223)) ) {
  printf("  RNG failed Runs test.\n");
  return 1;
}

if(longrun >= 34) {
  printf("  RNG failed LongRun test.\n");
  return 1;
}

 return 0;
}

int main(int argv,char **argc) {
  unsigned char random;
  int i=0;

  if(! (dev = fopen(RNG_DEVICE,"r"))) {
    printf("Open of "RNG_DEVICE" failed\n");
    exit(1);
  }

  for(i=0; i<RNG_LOOPS; i++){
    printf("Test: %d\n",(i+1));
    if(do_test()) {
       printf("Failed on test %d\n",i);
    }
  }
  printf("RNG correctly completed %d FIPS tests.\n",i);
  return 0;
}
