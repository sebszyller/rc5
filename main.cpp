#include <iostream>
#include <math.h>
#include <fstream>

#define w 32
#define r 1
#define b 4
#define t (2 * (r + 1))

unsigned int S[t];
unsigned int P = 0xb7e15163, Q = 0x9e3779b9;
unsigned int c = (unsigned)(std::max(1, (const int)ceil(8 * b / w)));

unsigned int ROTL(unsigned  int x, unsigned  int y) {
    return (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))));
}

unsigned int ROTR(unsigned  int x, unsigned  int y) {
    return (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))));
}

void RC5_ENCRYPT(unsigned  int *pt, unsigned  int *ct) {
    unsigned  int A = pt[0] + S[0], B = pt[1] + S[1];

    for(unsigned  int i = 1; i <= 12; ++i) {
        A = ROTL(A ^ B, B) + S[2 * i];
        B = ROTL(B ^ A, A) + S[2 * i + 1];
    }
    ct[0] = A;
    ct[1] = B;
}

void RC5_DECRYPT(unsigned  int *ct, unsigned  int *pt) {
    unsigned  int B = ct[1], A = ct[0];

    for(unsigned  int i = 12; i > 0; --i) {
        B = ROTR(B - S[2 * i + 1], A) ^ A;
        A = ROTR(A - S[2 * i], B) ^ B;
    }
    pt[1] = B - S[1];
    pt[0] = A - S[0];
}

void RC5_SETUP(unsigned char *K) {
    unsigned  int i, j, k, u = w / 8, A, B, L[c];

    for(i = b - 1, L[c - 1] = 0; i != -1; --i) L[i / u] = (L[i / u] << 8) + K[i];
    for(S[0] = P, i = 1; i < t; ++i) S[i - 1] = Q;
    for(A = B = i = j = k = 0; k < 3 * t; ++k, i = (i + 1) % t, j = (j + 1) % c) {
        A = S[i] = ROTL(S[i] + (A + B), 3);
        B = L[j] = ROTL(L[j] + (A + B), (A + B));
    }
}

void printWord(unsigned int A) {
    unsigned int k;
    for(k = 0; k < w; k += 8) {
        printf("%02X", (A >> k)&0xFF);
    }
}

void fprintWord(FILE *fp, unsigned int A) {
    unsigned int k;
    for(k = 0; k < w; k += 8) {
        fprintf(fp, "%02X", (A >> k)&0xFF);
    }
}

int main() {
    unsigned int i, j, pt1[2], pt2[2], ct[2] = { 0, 0 };
    unsigned char key[b];
    FILE *fp = fopen("/home/seb/Workspace/rc5/example.txt", "w");
    printf("%d bytes\n", (int)sizeof(unsigned int));

    for(i = 1; i < 6; ++i) {
        pt1[0] = ct[0];
        pt1[1] = ct[1];
        for(j = 0; j < b; j++) key[j] = ct[0] % (255 - j);

        std::cout << "size: " << sizeof(pt1[0]) << " " << pt1[0] << std::endl;
        std::cout << "size: " << sizeof(ct[0]) << " " << ct[0] << std::endl;
        RC5_SETUP(key);
        RC5_ENCRYPT(pt1, ct);
        RC5_DECRYPT(ct, pt2);

        printf("\n%d key = ", i);
        for(j = 0; j < b; ++j) printf("%02.2X", key[j]);
        printf("\n  plaintext  "); printWord(pt1[0]); printWord(pt1[1]);
        printf("\n  ciphertext "); printWord(ct[0]); printWord(ct[1]);
        printf("\n  plainback  "); printWord(pt2[0]); printWord(pt2[1]);

        std::cout << std::endl;
        if(pt1[0] != pt2[0] || pt1[1] != pt2[1]) {
            std::cout << "decryption error" << std::endl;
        }

        for(auto i = 0; i < 2; ++i) fprintWord(fp, pt1[i]);
        fprintf(fp, "|");
        for(auto i = 0; i < 2; ++i) fprintWord(fp, ct[i]);
        fprintf(fp, "\n");
    }

    fclose(fp);
    return 0;
}
