#include <iostream>
#include <cmath>

using namespace std;

// Function to check if a number is prime
bool isPrime(int num) {
    if (num <= 1) {
        return false;
    }
    for (int i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) {
            return false;
        }
    }
    return true;
}

// Function to find the greatest common divisor (GCD) of two numbers
int gcd(int a, int b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a % b);
}

// Function to perform prime factorization attack and find the private key
int primeFactorizationAttack(int n, int e) {
    int p, q; // prime factors of n
    int phi; // Euler's totient function value
    int d; // private exponent

    // Find prime factors p and q of n
    for (int i = 2; i < n; i++) {
        if (n % i == 0 && isPrime(i)) {
            p = i;
            q = n / i;
            break;
        }
    }
    phi = (p - 1) * (q - 1);

    // Find the multiplicative inverse of e modulo phi
    for (int i = 2; i < phi; i++) {
        if (gcd(i, phi) == 1) {
            d = i;
            break;
        }
    }

    return d;
}

int main() {
    int n, e, d; // RSA parameters: modulus (n), public exponent (e), private exponent (d)

    cout << "Enter modulus (n): ";
    cin >> n;

    cout << "Enter public exponent (e): ";
    cin >> e;

    // Perform prime factorization attack to find the private exponent (d)
    cout << "Performing prime factorization attack..." << endl;
    d = primeFactorizationAttack(n, e);
    cout << "Private Exponent (d): " << d << endl;

    return 0;
}
