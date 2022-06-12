/*----------------------------------cocks_IBE.h----------------------------------*/

#include "/usr/local/flint/include/flint/fmpz.h"
typedef struct
{
    fmpz_t N;
    fmpz_t p;
    fmpz_t q;
    fmpz_t alpha; // nombre random avec (alpha/N) == -1. 
                //permet d'avoir un fonction de hachage qui renvoie toujours un nombre sur Jn
                //si (a/N) == -1 alors a <- a*alpha
    fmpz_t mu;  //nombre random avec (mu/p) = (mu/q) = -1
    fmpz_t a;   //clef privee
    fmpz_t r;   //clef publique
    int square; //vaut 1 si a est
} struct_cocks;

#ifndef FILE_FOR_COCKS
#define FILE_FOR_COCKS "./file_cocks_135246352"
#endif // file for generate_prime

#ifndef NAME_HASH
#define NAME_HASH "sha256"
#endif

/* Interface pour chiffrer et dechiffrer avec le schema de cocks IBE.*/

/**
 * Setup:
 *      Fais l'étape du setup du schema de cocks avec lembda de bit de sécurité.
 *      Aloue et rempli les champs N, p, q et mu de s_c.
 *      Retourne EXIT_SUCCESS en cas de succés et EXIT_FAILLURE en cas d'échec
 **/
extern int setup(flint_bitcnt_t lembda, struct_cocks *s_c);

/**
 * extract:
 *      Fais l'étape de l'extract du schema de cocks.
 *      Aloue et rempli les champs a,r et square de s_c.
 *      Retourne EXIT_SUCCESS en cas de succés et EXIT_FAILLURE en cas d'échec.
 **/
extern int extract(char *id, struct_cocks *s_c);

/**
 * encrypt:
 *      Fais l'étape de l'encrypt du schema de cocks.
 *      Met le chiffrer de m dans c1 et c2 selon le schema de cocks.
 *      Retourne EXIT_SUCCESS en cas de succés et EXIT_FAILLURE en cas d'échec.
 **/
extern int encrypt(int m, fmpz_t c1, fmpz_t c2, struct_cocks *s_c);

/**
 * decrypt:
 *      Fais l'étape du decrypt du schema de cocks.
 *      Met le dechiffrer de c1 ou c2 selon le schema de cocks dans m.
 *      Retourne EXIT_SUCCESS en cas de succés et EXIT_FAILLURE en cas d'échec.
 **/
extern int decrypt(int *m, fmpz_t c1, fmpz_t c2, struct_cocks *s_c);
