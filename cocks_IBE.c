#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "./cocks_IBE.h"
#include "/usr/local/flint/include/flint/flint.h"
#include "/usr/local/flint/include/flint/fmpz.h"
#include <openssl/evp.h>
#include "standard.h"
#include "rand.h"
//variable global pour la bibliothéque rand.h
randctx rctx;

void interne_fmpz_randmod(fmpz_t f, const fmpz_t g);
int interne_fmpz_randprime(fmpz_t f, flint_bitcnt_t bits);

int main(int argc, char ** argv){
    if (argc < 2 && atoi(argv[1]) <= 0){
       fprintf(stderr, "Veuillez rentrer un nombre de bit\n");
       return EXIT_FAILURE;
    }
    if(atoi(argv[1]) <= 1024){
        fprintf(stderr, "Veuillez rentrer un nombre de bit plus grand car pas assez sécurisé\n");
       return EXIT_FAILURE;
    }
    //initialisation de nombre aléatoire
    ub4 i;
    for (i=0; i<RANDSIZ; ++i) {
        rctx.randrsl[i] = time(NULL);
    }
    randinit(&rctx, TRUE);
    struct_cocks *s_c = malloc(sizeof(struct_cocks));
    if(s_c == NULL){
        goto free;
    }
    if(setup(atoi(argv[1]), s_c) == EXIT_FAILURE){
        fprintf(stderr, "ERR: setup\n");
        goto free;
    }
    if(extract("06060606", s_c) == EXIT_FAILURE){
        fprintf(stderr, "ERR: extract\n");
        goto free;
    }
    fmpz_t c1;  //chiffrer
    fmpz_t c2;  //chiffrer
    int m = 0;  //clair
    int md = 0; //clar aprés dechiffrement
    int j = 0;
    fmpz_init(c1);
    fmpz_init(c2);
    while (j < 100){
        m = rand(&rctx);
        if(m%2){
            m = -1;
        }
        else{
            m = 1;
        }
        if(encrypt( m, c1, c2, s_c)
        == EXIT_FAILURE){
            fprintf(stderr, "ERR: encrypt\n");
           goto free;
        }
        if(decrypt( &md, c1, c2, s_c)
        == EXIT_FAILURE){
            fprintf(stderr, "ERR: encrypt\n");
            goto free;
        }
        printf("Le %dème message à crypter %d / Le %dème message trouvé  = %d\n", j, m, j, md);
        if(m != md){
            printf("###########ERREUR###########");
        }
        j++;
    }
    fmpz_clear(c1);
    fmpz_clear(c2);
    goto free;
free:
    //supprime des données aloué lors des opérations entre les grands nombres
    _fmpz_cleanup();
    //liberation des champs de s_c
    fmpz_clear(s_c->N);
    fmpz_clear(s_c->p);
    fmpz_clear(s_c->q);
    fmpz_clear(s_c->alpha);
    fmpz_clear(s_c->a);
    fmpz_clear(s_c->mu);
    fmpz_clear(s_c->r);
    free(s_c);
    
    return EXIT_SUCCESS;
}



int setup(flint_bitcnt_t lembda, struct_cocks *s_c){
    fmpz_init(s_c->p);
    fmpz_init(s_c->q);
    fmpz_init(s_c->N);
    fmpz_init(s_c->alpha);
    fmpz_init(s_c->mu);
    //genere p
    
    if(interne_fmpz_randprime(s_c->p, lembda/2) == EXIT_FAILURE){
        fprintf(stderr, "ERR: interne_fmpz_randprime for p");
        return EXIT_FAILURE;
    }
    printf("p a été généré\n");
    //genere q
    do{
        if(interne_fmpz_randprime(s_c->q, lembda/2) == EXIT_FAILURE){
            fprintf(stderr, "ERR: interne_fmpz_randprime for q");
            return EXIT_FAILURE;
        }
    } while(fmpz_equal(s_c->p, s_c->q));
    printf("q a été généré\n");
    //calcul N
    fmpz_mul(s_c->N, s_c->p, s_c->q);

    //genere alphe tq (alpha/N) == -1
    do {
        interne_fmpz_randmod(s_c->alpha, s_c->N);
    } while(fmpz_jacobi(s_c->alpha, s_c->N) != -1);
    
    //genere mu
    //boucle sur la generation d'un nombre tant que (mu/p) != -1 et (mu/q) != -1
    do {
        interne_fmpz_randmod(s_c->mu, s_c->N);
    } while(fmpz_jacobi(s_c->mu, s_c->p) != -1 || 
            fmpz_jacobi(s_c->mu, s_c->q) != -1);
    return EXIT_SUCCESS;
}

int extract(char *id, struct_cocks *s_c){
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    FILE *f_prime;
    fmpz_init(s_c->a);
    fmpz_init(s_c->r);
    f_prime = fopen(FILE_FOR_COCKS, "w+");
    if(f_prime == NULL){
        perror("fopen");
        return EXIT_FAILURE;
    }
    md = EVP_get_digestbyname(NAME_HASH);
    if (md == NULL) {
        printf("Unknown message digest %s\n", NAME_HASH);
        return EXIT_FAILURE;
    }
    //envellope contenant une structure avec 
    mdctx = EVP_MD_CTX_new();
    //
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, id, strlen(id));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    //ecris dans f_prime le hacher de id avec la bibliothéque openssl
    printf("haché crée\n");
    for (i = 0; i < md_len; i++){
         fprintf(f_prime, "%d", md_value[i]);
    }
    //récupére ce hasher pour la bibliothéque flint
    fseek(f_prime, 0, SEEK_SET);
    if (fmpz_fread(f_prime, s_c->a) < 0) {
        fprintf(stderr, "ERR: fmpz_read\n");
        return EXIT_FAILURE;
    }
    //si (a/N) == -1 alors on le multiplie par alpha tq (alpha/N) == -1
    //on aura (a/N) == 1
    if(fmpz_jacobi(s_c->a, s_c->N) != 1) {
        fmpz_mul(s_c->a, s_c->a, s_c->alpha);
    }
    //fait s_c->a <- (s_c->a) mod[s_c->N]
    fmpz_mod(s_c->a, s_c->a, s_c->N);

    //recherche de r² = a[N] ou r² = a*s_c->mu[N]
    fmpz_t u;
    fmpz_t t;
    fmpz_t v;
    fmpz_t s;
    fmpz_t tempo;
    fmpz_init(u);
    fmpz_init(t);
    fmpz_init(v);
    fmpz_init(s);
    fmpz_init(tempo);
    //calcule les identités de bézout de p et q
    fmpz_xgcd(tempo, u, v, s_c->p, s_c->q);
    if(fmpz_jacobi(s_c->a, s_c->p) == 1) {
        s_c->square = 1;
        fmpz_sqrtmod(s, s_c->a, s_c->p); //s racine carré de a mod p 
        fmpz_sqrtmod(t, s_c->a, s_c->q); //t racine carré de a mod q
    }
    else{
        s_c->square = 0;
        fmpz_mul(tempo, s_c->a, s_c->mu);
        fmpz_sqrtmod(s, tempo, s_c->p); //s racine carré de a*s_c->mu mod p 
        fmpz_sqrtmod(t, tempo, s_c->q); //s racine carré de a*s_c->mu mod q
    }
    printf("a généré \n");
    //fait ut et vs
    fmpz_mul(u, u, t);
    fmpz_mul(v, v, s);
    //fait upt + vqs
    fmpz_fmma(s_c->r, u, s_c->p, v, s_c->q);
    //fait upt + vqs [N]
    fmpz_mod(s_c->r, s_c->r, s_c->N);
    printf("r généré \n");
    fmpz_clear(u);
    fmpz_clear(t);
    fmpz_clear(v);
    fmpz_clear(s);
    fmpz_clear(tempo);
    fclose(f_prime);
    return EXIT_SUCCESS;
}

int encrypt(int m, fmpz_t c1, fmpz_t c2, struct_cocks *s_c){
    
    fmpz_t t1;
    fmpz_t t2;
    fmpz_t t1inv;
    fmpz_t t2inv;
    fmpz_init(t1);
    fmpz_init(t2);
    fmpz_init(t1inv);
    fmpz_init(t2inv);
    //genere t1 tq (alpha/N) == 1 et son inverse t1inv
    do{
        interne_fmpz_randmod(t1, s_c->N);
    } while(fmpz_jacobi(t1, s_c->N) != m || fmpz_invmod(t1inv, t1, s_c->N) == 0);
    //genere t2 tq (alpha/N) == 1 et son inverse t2inv
    do{
        interne_fmpz_randmod(t2, s_c->N);
    } while(fmpz_jacobi(t2, s_c->N) != m || fmpz_invmod(t2inv, t2, s_c->N) == 0);
    
    //crée c1
    fmpz_mul(c1,s_c->a, t1inv);
    fmpz_add(c1, t1, c1);
    fmpz_mod(c1, c1, s_c->N);
    //crée c2
    fmpz_mul(c2,s_c->a, t2inv);
    fmpz_mul(c2, c2, s_c->mu);
    fmpz_add(c2, t2, c2);
    fmpz_mod(c2, c2, s_c->N);
    fmpz_clear(t1);
    fmpz_clear(t2);
    fmpz_clear(t1inv);
    fmpz_clear(t2inv);
    return EXIT_SUCCESS;
}

int decrypt(int *m, fmpz_t c1, fmpz_t c2, struct_cocks *s_c){
    fmpz_t tempo;
    fmpz_init(tempo);
    //2*r
    fmpz_mul_si(tempo, s_c->r, 2);
    //c+2*r
    if(s_c->square){
        fmpz_add(tempo, tempo, c1);
    }
    else{
        fmpz_add(tempo, tempo, c2);
    }
    //((c+2*r)/N)
    *m = fmpz_jacobi(tempo, s_c->N);
    fmpz_clear(tempo);
    return EXIT_SUCCESS;
}

//f devient un nombre random entre 2^(bits-1) et 2^(bits)-1
//bits doit être supérieur à FLINT_BITS - 2
void interne_fmpz_randmod(fmpz_t f, const fmpz_t m) {
    flint_rand_t state;
    long unsigned int rand;
    flint_randinit(state);
    __mpz_struct *mpz_ptr = _fmpz_promote(f);
    _flint_rand_init_gmp(state);
    rand = (long unsigned int) rand(&rctx);
    gmp_randseed_ui(state->gmp_state, rand);
    mpz_urandomb(mpz_ptr, state->gmp_state, fmpz_bits(m)*2);
    fmpz_mod(f, f, m);
    flint_randclear(state);
}

int interne_fmpz_randprime(fmpz_t f, flint_bitcnt_t bits) {
    if(bits < FLINT_BITS - 2){
        fprintf(stderr, "veuillez rentrer un nombre de bit supérieur");
        return EXIT_FAILURE;
    }
    flint_rand_t state;
    long unsigned int rand;
    flint_randinit(state);
    __mpz_struct *mpz_ptr = _fmpz_promote(f);
    _flint_rand_init_gmp(state);
    rand = (long unsigned int) rand(&rctx);
    gmp_randseed_ui(state->gmp_state, rand);
    mpz_urandomb(mpz_ptr, state->gmp_state, bits);
    fmpz_nextprime(f, f, 0);
    flint_randclear(state);
    return EXIT_SUCCESS;
}
