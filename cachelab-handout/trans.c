/*
 * trans.c - Matrix transpose B = A^T
 *
 * Each transpose function must have a prototype of the form:
 * void trans(int M, int N, int A[N][M], int B[M][N]);
 *
 * A transpose function is evaluated by counting the number of misses
 * on a 1KB direct mapped cache with a block size of 32 bytes.
 */
#include "cachelab.h"

int is_transpose(int M, int N, int A[N][M], int B[M][N]);

/*
 * transpose_submit - This is the solution transpose function that you
 *     will be graded on for Part B of the assignment. Do not change
 *     the description string "Transpose submission", as the driver
 *     searches for that string to identify the transpose function to
 *     be graded.
 */
char transpose_submit_desc[] = "Transpose submission";
void transpose_submit(int M, int N, int A[N][M], int B[M][N]) {
  int a, b, c, d, e, f, g, h;
  int n = 8 * (N / 8);
  int m = 8 * (M / 8);
  for (int i = 0; i < n; i += 8) {
    for (int j = 0; j < m; j += 8) {
      for (int ii = i; ii < i + 8; ++ii) {
        a = A[ii][j];
        b = A[ii][j + 1];
        c = A[ii][j + 2];
        d = A[ii][j + 3];
        e = A[ii][j + 4];
        f = A[ii][j + 5];
        g = A[ii][j + 6];
        h = A[ii][j + 7];

        B[j][ii] = a;
        B[j + 1][ii] = b;
        B[j + 2][ii] = c;
        B[j + 3][ii] = d;
        B[j + 4][ii] = e;
        B[j + 5][ii] = f;
        B[j + 6][ii] = g;
        B[j + 7][ii] = h;
      }
    }
  }

  for (int i = 0; i < n; i++) {
    for (int j = m; j < M; j++) {
      B[j][i] = A[i][j];
    }
  }

  for (int i = n; i < N; i++) {
    for (int j = 0; j < M; j++) {
      B[j][i] = A[i][j];
    }
  }
}

/*
 * You can define additional transpose functions below. We've defined
 * a simple one below to help you get started.
 */

/*
 * trans - A simple baseline transpose function, not optimized for the cache.
 */
char trans_desc[] = "Simple row-wise scan transpose";
void trans(int M, int N, int A[N][M], int B[M][N]) {
  int i, j, tmp;

  for (i = 0; i < N; i++) {
    for (j = 0; j < M; j++) {
      tmp = A[i][j];
      B[j][i] = tmp;
    }
  }
}

/*
 * registerFunctions - This function registers your transpose
 *     functions with the driver.  At runtime, the driver will
 *     evaluate each of the registered functions and summarize their
 *     performance. This is a handy way to experiment with different
 *     transpose strategies.
 */
void registerFunctions() {
  /* Register your solution function */
  registerTransFunction(transpose_submit, transpose_submit_desc);

  /* Register any additional transpose functions */
  registerTransFunction(trans, trans_desc);
}

/*
 * is_transpose - This helper function checks if B is the transpose of
 *     A. You can check the correctness of your transpose by calling
 *     it before returning from the transpose function.
 */
int is_transpose(int M, int N, int A[N][M], int B[M][N]) {
  int i, j;

  for (i = 0; i < N; i++) {
    for (j = 0; j < M; ++j) {
      if (A[i][j] != B[j][i]) {
        return 0;
      }
    }
  }
  return 1;
}
