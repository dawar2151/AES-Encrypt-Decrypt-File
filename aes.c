/**
*
* @author : Zouhair ET-TAOUSY
**/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#if defined(__APPLE__)
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#define SHA1 CC_SHA1
#else
#include <openssl/md5.h>
#endif       // log, pow
#include "aes.h"


void afficher_le_bloc(uchar *M) {
  printf("Resultat : ");
  for (int i=0; i<4; i++) { // Lignes 0 à 3
    for (int j=0; j<4; j++) { // Colonnes 0 à 3
      printf ("%02X", M[4*j+i]); 
    } 
  }
  printf("\n"); 
}
void afficher_le_bloc_dechiffre(uchar *M) {
  printf("Resultat : ");
  for (int i=0; i<16; i++) { 
      printf ("%02X", M[i]); 
  }
  printf("\n"); 
}

int main(int argc, char *argv[]) {
  
  //Génération   de la clef long apartir d'un mot de passe passé en paramètre
  if( argv[2] && argv[3] ){
    if(strcmp(argv[3], " ") != 0){
     // Si l'utilisateur tap un mot de passe pour le chiffrement
    char *output = str2md5(argv[3], strlen(argv[3]));
    printf("La Cle utilisée est : %s\n", output);
    for (size_t count = 0; count < sizeof K/sizeof *K; count++) {
        sscanf(output, "%2hhx", &K[count]);
        output += 2;
    } 
    setW();//Genérer nouveau clef long
   }
  }
  if(strcmp(argv[1], "-e") == 0){

    if(argv[2]){//chiffrer un fichier
      cryptFile(argv[2]);
    }else{
      chiffrer();
      afficher_le_bloc(State);
    } 
      
  }else if(strcmp(argv[1], "-d") == 0){ //dechiffrer un fichier
      if(argv[2]){
          decryptFile(argv[2]);
      }else{
        dechiffrer();
        afficher_le_bloc_dechiffre(State);
      }  
  }else{
      chiffrer();
      afficher_le_bloc(State);
  }  
    exit(EXIT_SUCCESS);
}
void generateInitVector(){
  for (int i = 0; i < 16; ++i)
  {
     V[i] = rand()%255;
  }
}
void chiffrer(void){
  int i;
  AddRoundKey(0);
  for (i = 1; i < Nr; i++) {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(i);
  }
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);
}
void dechiffrer(void){
  int i;
  AddRoundKey(Nr);
  for (i = Nr-1; i > 0; i--) {
    InvSubBytes();
    InvShiftRows();
    AddRoundKey(i);
    InvMixColumns();  
  }
  InvShiftRows();
  InvSubBytes();
  AddRoundKey(0);
}
/* Fonction mystérieuse qui calcule le produit de deux octets */

uchar gmul(uchar a, uchar b) {
  uchar p = 0;
  uchar hi_bit_set;
  int i;
  for(i = 0; i < 8; i++) {
    if((b & 1) == 1) 
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if(hi_bit_set == 0x80) 
      a ^= 0x1b;    
    b >>= 1;
  }
  return p & 0xFF;
}

/* Partie à compléter pour ce TP */

void SubBytes(void){
  for (int i = 0; i < 16; ++i)
  {
    State[i] = SBox[State[i]];
  }
};
void ShiftRows(void){
  unsigned char tmp[16];
  tmp[0] = State[0];
  tmp[1] = State[5];
  tmp[2] = State[10];
  tmp[3] = State[15];

  tmp[4] = State[4];
  tmp[5] = State[9];
  tmp[6] = State[14];
  tmp[7] = State[3];
  
  tmp[8] = State[8];
  tmp[9] = State[13];
  tmp[10] = State[2];
  tmp[11] = State[7];

  tmp[12] = State[12];
  tmp[13] = State[1];
  tmp[14] = State[6];
  tmp[15] = State[11];
  for (int i = 0; i < 16; ++i)
  {
    State[i] = tmp[i];
  }
};
void MixColumns(void){
    unsigned char tmp[16];
   for (int c = 0; c < 4; c++) {
        //printf("link : %d %d %d %d /n",4*c+0,4*c+1,4*c+2,4*c+3);
        tmp[4*c+0] = gmul(0x02, State[4*c+0]) ^ gmul(0x03, State[4*c+1]) ^ State[4*c+2] ^ State[4*c+3];
        tmp[4*c+1] = State[4*c+0] ^ gmul(0x02, State[4*c+1]) ^ gmul(0x03, State[4*c+2]) ^ State[4*c+3];
        tmp[4*c+2] = State[4*c+0] ^ State[4*c+1] ^ gmul(0x02, State[4*c+2]) ^ gmul(0x03, State[4*c+3]);
        tmp[4*c+3] = gmul(0x03, State[4*c+0]) ^ State[4*c+1] ^ State[4*c+2] ^ gmul(0x02, State[4*c+3]);
    }
    for (int i=0; i<16; i++) { 
      State[i] = tmp[i];
    }
};
void AddRoundKey(int r){

    for (int i = 0; i < 16; ++i)
    {
      State[i] = State[i] ^ W[r*16+i];
    }
  
};
/* AES decrypt methodes */
void InvSubBytes(void){
  for (int i = 0; i < 16; ++i)
  {
    State[i] = InvSBox[State[i]];
  }
}
void InvShiftRows(void){
  unsigned char tmp[16];
  tmp[0] = State[0];
  tmp[5] = State[1];
  tmp[10] = State[2];
  tmp[15] = State[3];

  tmp[4] = State[4];
  tmp[9] = State[5];
  tmp[14] = State[6];
  tmp[3] = State[7];
  
  tmp[8] = State[8];
  tmp[13] = State[9];
  tmp[2] = State[10];
  tmp[7] = State[11];

  tmp[12] = State[12];
  tmp[1] = State[13];
  tmp[6] = State[14];
  tmp[11] = State[15];
  for (int i = 0; i < 16; ++i)
  {
    State[i] = tmp[i];
  }
};
void InvMixColumns(void){
    unsigned char tmp[16];
   for (int c = 0; c < 4; c++) {
        //printf("link : %d %d %d %d /n",4*c+0,4*c+1,4*c+2,4*c+3);
        tmp[4*c+0] = gmul(0x0E, State[4*c+0]) ^ gmul(0x0B, State[4*c+1]) ^ gmul(0x0D,State[4*c+2]) ^ gmul(0x09,State[4*c+3]);
        tmp[4*c+1] = gmul(0x09,State[4*c+0]) ^ gmul(0x0E, State[4*c+1]) ^ gmul(0x0B, State[4*c+2]) ^ gmul(0x0D,State[4*c+3]);
        tmp[4*c+2] = gmul(0x0D,State[4*c+0]) ^ gmul(0x09,State[4*c+1]) ^ gmul(0x0E, State[4*c+2]) ^ gmul(0x0B, State[4*c+3]);
        tmp[4*c+3] = gmul(0x0B, State[4*c+0]) ^ gmul(0x0D,State[4*c+1]) ^ gmul(0x09,State[4*c+2]) ^ gmul(0x0E, State[4*c+3]);
    }
    for (int i=0; i<16; i++) { 
      State[i] = tmp[i];
    }
};
char* padding(char* fileName){
  char *fichierDest="pkcs5-butokuden.jpg";
  int nb_octets_lus, etendu, l, k = 16;
  size_t br;
  int size;
  char *nom_du_fichier = fileName;
  FILE *fsDest = fopen (fichierDest, "wb");
  FILE *fsSrc = fopen (nom_du_fichier, "rb");
  fseek(fsSrc, 0, SEEK_END); // seek to end of file
  size = ftell(fsSrc); // get current file pointer
  fseek(fsSrc, 0, SEEK_SET); // seek back to beginning of file
   do {
      br=fread(buffer,1,sizeof(buffer),fsSrc);
      fwrite(buffer,1,br,fsDest);
  } while(br==sizeof(buffer));
  etendu = k - ( size % k);
  for (int i = 0; i < etendu; i++)
  {
        int c;
       c = fputc(etendu, fsDest);
  }
  fclose(fsSrc);
  fclose(fsDest);
  return fichierDest;

}
void copyFile(FILE *fdest,FILE *fsrc) {
    size_t br;
    do {
        br=fread(buffer,1,sizeof(buffer),fsrc);
        fwrite(buffer,1,br,fdest);
    } while(br==sizeof(buffer));
}
char *str2md5(const char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char*)malloc(33);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return out;
}
void affiche_la_clef(uchar *clef, int longueur)
{
  for (int i=0; i<longueur; i++) { printf ("%02X ", clef[i]); }
  printf("\n");
}

void RotWord(uchar *tmp)
{
  uchar k;
  k = tmp[0];
  tmp[0] = tmp[1];
  tmp[1] = tmp[2];
  tmp[2] = tmp[3];
  tmp[3] = k;
} 
void SubWord(uchar *tmp)
{
  tmp[0] = SBox[tmp[0]];
  tmp[1] = SBox[tmp[1]];
  tmp[2] = SBox[tmp[2]];
  tmp[3] = SBox[tmp[3]];
} 
void calcule_la_clef_etendue(uchar *K, int long_K, uchar *W, int long_W, int Nr, int Nk)
{
  uchar *tmp;
  printf("%d", Nk);
  tmp =  malloc(sizeof(4));
    for(int i=0; i < Nk; i++){
     W[i] = K[i];
     
    }
    for (int i = 0; i < (4*(Nr+1)); ++i)
    { 
      for(int j = 0;j < 4 ; j++){
        tmp[j] = W[(i-1) * 4 + j];
      }
      if (i % Nk == 0){ 
        RotWord(tmp);
        SubWord(tmp);
        tmp[0] = tmp[0] ^ Rcon[i/Nk];
        tmp[1] = tmp[2] ^ Rcon[i/Nk];
        tmp[3] = tmp[3] ^ Rcon[i/Nk];
        tmp[4] = tmp[4] ^ Rcon[i/Nk];

      }else if((Nk > 6) && (i % Nk == 4)){
        SubWord(tmp);
      }
      W[i*4+0] = W[(i-Nk)*4+0] ^ tmp[0];
      W[i*4+1] = W[(i-Nk)*4+1] ^ tmp[1];
      W[i*4+2] = W[(i-Nk)*4+2] ^ tmp[2];
      W[i*4+3] = W[(i-Nk)*4+3] ^ tmp[3];

    }     
  }
  void setW(){
    // La longueur max. de la clef courte est 32 octets
    int long_de_la_clef = 16 ;
     // La longueur max. de la clef étendue est (14+1)*16=240 octets
    int Nr, Nk;
    if (long_de_la_clef == 16){ Nr = 10; Nk = 4; }
    else if (long_de_la_clef == 24){ Nr = 12; Nk = 6; }
         else { Nr = 14; Nk = 8; }
    int long_de_la_clef_etendue = 4*(4*(Nr+1));
    calcule_la_clef_etendue(K, long_de_la_clef, W, long_de_la_clef_etendue, Nr, Nk);  
  }  
  void cryptFile(char* paddredFile){
     char * fichierpkcs5 = padding(paddredFile);
          char *fichierDest="aes-butokuden.jpg";
          int nb_octets_lus, etendu, l, k = 16;
          FILE *fsDest = fopen (fichierDest, "wb");
          FILE *fsSrc = fopen (fichierpkcs5, "rb");
          int isFirstSizeOctet = 1;
          generateInitVector();
          fwrite(V,sizeof(buffer),1,fsDest); 
           do{
              br=fread(buffer,1,sizeof(buffer),fsSrc);
              c = 0;
              uchar tmp[16];
              for (int i=0; i<16; i++) {  
                  if(isFirstSizeOctet == 1)                    
                     tmp[i] = buffer[i] ^ V[i];
                  else
                      tmp[i] = buffer[i] ^ State[i];       
              }
              for (int i = 0; i < 16; i++)
              {
                State[i] = tmp[i];
              }
              isFirstSizeOctet = 0;    
              chiffrer();
              if(br > 0) 
              fwrite(State,sizeof(buffer),1,fsDest); 
            }while(br==sizeof(buffer));
            printf("chiffrement de butokuden.jpg en aes-butokuden.jpg\n");

  }
  void decryptFile(char *cryptedFile){
    uchar tmpDechiffer[16];
          uchar blockToSave[16];
          char *fichierDest="aes-aes-butokuden.jpg";
          int nb_octets_lus, etendu, l, k = 16;
          FILE *fsDest = fopen (fichierDest, "wb");
          FILE *fsSrc = fopen (cryptedFile, "rb");
          int isFirstSizeOctet = 1;
          int removeVectorInit = 1;

           do{
              // Copy crypted State
              for (int i=0; i<16; i++) {
                  tmpDechiffer[i] = buffer[i];
              }
              // Read data from buffer
              br=fread(buffer,1,sizeof(buffer),fsSrc);
              // is its the first initialised victor
              if( removeVectorInit ){
                for (int i=0; i<16; i++) {
                  V[i] = buffer[i];
                }
                removeVectorInit = 0;
              }else{
                c = 0;
                for (int i=0; i<16; i++) { // Lignes 0 à 3              
                     State[i] = buffer[i]; 
                }      
                dechiffrer();
                uchar tmp[16];
                if(isFirstSizeOctet){
                  c = 0;
                  for (int i=0; i<16; i++) { // Lignes 0 à 3    
                      tmp[i] = State[i] ^ V[i];
                    //c++;
                  }
                  isFirstSizeOctet = 0;  
                }else{
                  for (int i=0; i<16; i++) { // Lignes 0 à 3  
                      tmp[i] = State[i] ^ tmpDechiffer[i]; 
                  }   

                }
                if(br > 0){
                  for (int i=0; i<16; i++) { // Colonnes 0 à 3     
                      blockToSave[i] = tmp[i];
                    }
                  fwrite(blockToSave,sizeof(buffer),1,fsDest);
                }  
              } 

            }while(br==sizeof(buffer));
            printf("dechiffrement de butokuden.jpg en aes-aes-butokuden.jpg \n");
  }
