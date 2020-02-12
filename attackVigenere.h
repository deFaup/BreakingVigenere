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

std::vector<std::string> Vigenere(const std::string& cipherText);
int findLength(const std::string& cipherText, std::vector<int>& keyLengths);
std::vector<int> findPatternDistances(const std::string& cipherText);
void addDivisors(const int n, std::vector<int>& divisors);
int findGCD(std::vector<int>& divisors);

std::string monoAlphabeticAttack(const std::string& cipherText, int keyLength);
std::vector<std::string> getSubstrings(const std::string& inputString, const unsigned long key_length);
char attackCipherWithStatistics(std::string& cipherString);
std::vector<double> getFrequencies(const std::string& inputString);
std::vector<double> getSquareFreqPermutation(const std::vector<double>& frequencies);
int returnIndexClosestToValue(const std::vector<double>& inputValues, double target_value, double* savedValue= nullptr);

std::string getPlainText(const std::vector<std::string>& substrings, const int cipherLength, const int key_length);

double abs(const double value);

double getSumOfSquareProbabilities(std::vector<double>& probVec);


#endif //ATTACKONVIGENERE_ATTACKVIGENERE_H
