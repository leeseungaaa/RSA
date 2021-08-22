#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
  BN_CTX *ctx = BN_CTX_new(); 
	
  BIGNUM *r = BN_new();
  BIGNUM *dv = BN_new(); 
  BIGNUM *x_mul = BN_new();
  BIGNUM *y_mul = BN_new();
  BIGNUM *t; 

  BIGNUM *_a = BN_new();
  BN_copy(_a,a);
  BIGNUM *_b = BN_new();
  BN_copy(_b,b);
  
  BIGNUM *x_pre_pre = BN_new(); 
  BN_dec2bn(&x_pre_pre, "1");
  
  BIGNUM *x_pre = BN_new(); 
  BN_dec2bn(&x_pre, "0");
  
  BIGNUM *y_pre_pre = BN_new(); 
  BN_dec2bn(&y_pre_pre, "0");
  
  BIGNUM *y_pre = BN_new(); 
  BN_dec2bn(&y_pre, "1");
	
  if (BN_cmp(_a, _b) < 0) {
     t = _a;
     _a = _b;
     _b = t;
     
     t = x;
     x = y;
     y = t;
  }

  while (!BN_is_zero(_b)) {

        if(!BN_div(dv, r, _a, _b, ctx)){
          goto err;
        }
       
        BN_mul(x_mul, x_pre, dv, ctx);
        BN_mul(y_mul, y_pre, dv, ctx);
        
       	BN_sub(x, x_pre_pre, x_mul);
        BN_sub(y, y_pre_pre, y_mul);
        
        BN_copy(_a,_b);
        BN_copy(_b,r);
        
        BN_copy(x_pre_pre,x_pre) ;
        BN_copy(x_pre,x) ;
        
        BN_copy(y_pre_pre,y_pre) ;
        BN_copy(y_pre,y) ;
    }
  
    BN_copy(r,_a);
  
    BN_copy(x,x_pre_pre) ;
    BN_copy(y,y_pre_pre) ;
	
	if(ctx != NULL) BN_CTX_free(ctx);
	if(dv != NULL) BN_free(dv);
	if(x_mul != NULL) BN_free(x_mul);
	if(y_mul != NULL) BN_free(y_mul);
	if(x_pre_pre != NULL) BN_free(x_pre_pre);
	if(x_pre != NULL) BN_free(x_pre);
	if(y_pre_pre != NULL) BN_free(y_pre_pre);
	if(y_pre != NULL) BN_free(y_pre);
	
	return y;
	
err:
  return NULL;
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *dv = BN_new();
	BIGNUM *_e = BN_new();

	BN_copy(_e,e);

	BIGNUM * A = BN_new(); 
	BN_copy(A, a);

	for (int i=BN_num_bits(e)-2; i>=0; i --){
		
			BN_mod_mul(A, A, A, m, ctx);
		
			if (BN_is_bit_set(_e,i)) {
					BN_mod_mul(A, A, a, m, ctx);
			}
	
	}
 
 	BN_copy(r,A);
 
 	if(ctx != NULL) BN_CTX_free(ctx);
 	if(dv != NULL) BN_free(dv);
 	if(_e != NULL) BN_free(_e);
 	if(A != NULL) BN_free(A);

}

typedef struct _b10rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB10_RSA;


BOB10_RSA *BOB10_RSA_new(){
    BOB10_RSA *p = malloc(sizeof(BOB10_RSA));
    
    p->e = BN_new();
    p->d = BN_new();
    p->n = BN_new();
    
    return p;
};


int BOB10_RSA_free(BOB10_RSA *b10rsa){

    BN_free(b10rsa->e);
    BN_free(b10rsa->d);
    BN_free(b10rsa->n);

    free(b10rsa);

};

BIGNUM *GenProbPrime(int pBits){

    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *p = BN_new();
    BN_rand(p, pBits, 1, 1); 

    BIGNUM *q = BN_new();
    
    BIGNUM *a = BN_new(); 
    
    BIGNUM *res = BN_new();

    BIGNUM *_p = BN_new();

    BIGNUM *_1 = BN_new();
    BN_dec2bn(&_1, "1");

    BIGNUM *__1 = BN_new();
    BN_dec2bn(&__1, "-1");

    BIGNUM *_2 = BN_new();
    BN_dec2bn(&_2, "2");

    BIGNUM *aa = BN_new();

    BIGNUM *_cnt = BN_new();

    // 소수 나올 때 까지 랜덤수 += 2 해가면서 진행
    while(1){
    
    BN_add(p, p, _2);
    BN_sub(_p, p, _1);

    int count = 0;
    
    for(int i=0; i<BN_num_bits(_p); i++){

        if(!BN_is_bit_set(_p, i)) count += 1;
        else {break;}

    }

    char s1[100] = {};
    sprintf(s1, "%d", count);

    BN_dec2bn(&_cnt, s1);
    BN_exp(aa, _2, _cnt, ctx);
    BN_div(q, NULL, _p, aa, ctx);

    // a 값 랜덤하게 생성해서 10번 test
    for(int j=0; j<10; j++) {

        BN_rand(a, 50, 1, 1);

        ExpMod(res,a,q,p);
    
        if(!BN_cmp(res, _1)){continue;}
        
        for(int i=0; i<count; i++) {
           
            if (!BN_cmp(res, __1) || !BN_cmp(res, _p)) { break; }

            BN_mul(q, q, _2, ctx);
            ExpMod(res,a,q,p);
            
        } 
    }
    
    if(!BN_cmp(res, _1)) break;
    if (!BN_cmp(res, __1) || !BN_cmp(res, _p))  break; 
}

if(ctx != NULL) BN_CTX_free(ctx);
if(q != NULL) BN_free(q);
if(a != NULL) BN_free(a);
if(res != NULL) BN_free(res);
if(_p != NULL) BN_free(_p);
if(_1 != NULL) BN_free(_1);
if(__1 != NULL) BN_free(__1);
if(_2 != NULL) BN_free(_2);
if(aa != NULL) BN_free(aa);
if(_cnt != NULL) BN_free(_cnt);

return p;

};

int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits){
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
 //   BN_hex2bn(&p, "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
 //   BN_hex2bn(&q, "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");

    unsigned int pBits = nBits/2;

    p =  GenProbPrime(pBits);
    q =  GenProbPrime(pBits);

    BIGNUM *phi = BN_new();

    BIGNUM *_p = BN_new();
    BIGNUM *_q = BN_new();

    BIGNUM *_1 = BN_new();
    BN_dec2bn(&_1, "1");

    BIGNUM *_0 = BN_new();
    BN_dec2bn(&_0, "0");

    BN_mul(b10rsa->n, p, q, ctx);
    
    BN_sub(_p, p, _1);
    BN_sub(_q, q, _1);
    BN_mul(phi, _p, _q, ctx);
    
    BN_hex2bn(&b10rsa->e, "10001");

    b10rsa->d = XEuclid(x,y,phi,b10rsa->e);
    if (BN_cmp(_0, b10rsa->d)){ 
        BN_add(b10rsa->d, b10rsa->d, phi);
    }

};

int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa){

    ExpMod(c,m,b10rsa->e,b10rsa->n);

};

int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa){

    ExpMod(m,c,b10rsa->d,b10rsa->n);

};


void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
    BOB10_RSA *b10rsa = BOB10_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){ 
            PrintUsage();
            return -1;
        } 
        BOB10_RSA_KeyGen(b10rsa,1024); 
        printf("n: ");
        BN_print_fp(stdout,b10rsa->n);
        printf("\n");
        printf("e: ");
        BN_print_fp(stdout,b10rsa->e);
        printf("\n");
        printf("d: ");
        BN_print_fp(stdout,b10rsa->d); 
        printf("\n");
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){ 
            PrintUsage();
            return -1;
        } 
        BN_hex2bn(&b10rsa->n, argv[3]); 
        BN_hex2bn(&in, argv[4]); 
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b10rsa->e, argv[2]); 
            printf("c: ");
            BOB10_RSA_Enc(out,in, b10rsa); 
        }else if(!strncmp(argv[1],"-d",2)){ 
            BN_hex2bn(&b10rsa->d, argv[2]);  
            printf("m: ");
            BOB10_RSA_Dec(out,in, b10rsa); 
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
        printf("\n");
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b10rsa!= NULL) BOB10_RSA_free(b10rsa);

    return 0;
}
