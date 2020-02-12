//
// Created by gregoire on 10/02/2020.
//

#ifndef ATTACKONVIGENERE_ATTACKVIGENERE_H
#define ATTACKONVIGENERE_ATTACKVIGENERE_H

#include <iostream>
#include <algorithm> //sort
#include <map>
#include <vector>
#include <string>

std::string Vigenere(std::string cipherText);
std::vector<std::string> getSubstrings(const std::string& cipherText, unsigned long key_length);
std::vector<double> getFrequencies(const std::string& cipherString);
std::vector<double> getSquareFreqPermutation(std::vector<double>& frequencies);
double getSumOfSquareProbabilities(std::vector<double>& probVec);
int returnIndexClosestToValue(std::vector<double> allSquareProbabilities, double target_value, double* squareProbToSave= nullptr);
char attackCipherWithStatistics(std::string& cipherString);
std::string getPlainText(std::vector<std::string>& substrings, int cipherLength, int key_length);
double abs(double value);

int findLength(std::string& cipherText);
std::vector<int> findPatternDistances(std::string& cipherText);
void addDivisors(int n, std::vector<int>& divisors);
int findGCD(std::vector<int>& divisors);


#endif //ATTACKONVIGENERE_ATTACKVIGENERE_H
