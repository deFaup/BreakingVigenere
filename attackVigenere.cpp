#include "attackVigenere.h"

#define SQUARE_PROB_SUM (0.065)
#define MIN_NUMBER_CHARACTERS 16
#define MIN_KEY_LENGTH 1
#define MAX_KEY_LENGTH 50

/* Breaking Vigenere cypher when length t is unknown */

double english_probabilities[26] = {8.2/100, 1.5/100, 2.8/100, 4.2/100, 12.7/100, 2.2/100, 2.0/100,
6.1/100, 7.0/100, 0.1/100, 0.8/100, 4.0/100, 2.4/100, 6.7/100,
7.5/100, 1.9/100, 0.1/100, 6.0/100, 6.3/100, 9.0/100, 2.8/100,
1.0/100, 2.4/100, 2.0/100, 0.1/100, 0.1/100};

int main()
{
    std::cout << "Hello, World!" << std::endl;
    std::string plaintext1 ("LLGFIYUSWJWGUVAHXQYVCHLAAWPGXGSWATYVAXKKMPLITWWVARIKXWVIPLWYGYNVPQNIKLWQXETKXWVIPLWJSZGDICJRVLLTWIEZERLITKMPLLGUSWJWGAREDYFARILLGZMULSTAGCDGKHLGJXJWTGJJGUXUWGWJMVQEPVXJWTUWYFGVCFHQEKGFITSXQJQQJIVGTKUWYAPNTIIAZGFWQGRVZIPWBVULCHXGJAKDPDWXJWFNGGMUMRZITAXYAPNTIHARKKLGVMPEEA");
    std::string plaintext2 ("IYMIEYADLZNEEPNGBJGTYEYGDSPMIVINYDSIZBDSKLIVZZSVGCXAOUFCCKAROWJSCWQEKRHFNVRURJUMITUFPMMGECPCKBCRGCRYIKTGPHZVOHGADLZNEKLRCCYIPEIYMCIURDIQXANAXGPZRVFTGMMFGAIJMXUTGIPIIDVFTGAZUFMGRVYOOETEMMAVMGDWMEVMEZKNWKJASMBIXCCJWJNVFTEMSTEFPGBZRYGACJZTJCQCWXKEGEYMMIVUXCTWEHGCZACEFGCDIT");

    std::string cipherLength1("RZZOXZCYTYRPGPCJZYPMPWZHTDLYPILXAWPZQCLYOZXEPIEHCTEEPYTYPYRWTDSESTDAWLTYEPIETDRZTYREZDPCGPLDPILXAWPEPDEEZDPPHSPESPCZCYZEESPDELETDETNDRTGPYMJESPACZQPDDZCLCPRZZOZCYZETQESPJLCPESPYTDSZFWOQTYOGPCJPLDTWJESLEXJVPJHLDZYWJXLOPZQZYPWPEEPC");
    std::string cipherLength5("RSARZZVZWARIHSEJSZSOPPAKVDEZSKLQBZRZJDOAOSYHRIXIFVEXQBVYIZUYTWTHUTWBZNTRFSKEMEUBTRSHBDIDJRLWQLNXTXSGPWFHBDIQKUPXTSEZVZCGELQGGLXUGGTGEUVGIZPLELQDEZJQGFZVMFRRSARBCRAHVQXTSLLVQHUPRUGUZYXRSTRPJRCCQOFTPKHULXYMXPCIOFZRXMZLHQCSZRQZREXQF");

    std::vector<std::string> plainTexts(Vigenere(cipherLength5));
    for (auto text:plainTexts)
        std::cout << text << "\n\n\n";

/*
    plaintext = Vigenere(cipherLength5);
    std::cout << plaintext << "\n";

    plaintext = Vigenere(plaintext2);
    std::cout << plaintext << "\n";
*/

    return 0;
}

/*
 * @Param:
 *      cipherText:   Reference to a Mono-alphabetic cipher text (capital letters only)
 *      keyLength:    keyLength to use to break the cipher
 * @Return:
 *      plainText:    cipherText input deciphered with a key of size keyLength.
 *                      Statistical approach used to find the best shift to break the cipher
*/
std::string monoAlphabeticAttack(const std::string& cipherText, const int keyLength)
{
    std::string vigenereKey(keyLength,'-');

    std::vector<std::string> substrings = getSubstrings(cipherText, keyLength);
    if (substrings[0].size() < MIN_NUMBER_CHARACTERS)
        return "";
    for (int i=0; i < keyLength; ++i)
        vigenereKey[i] = attackCipherWithStatistics(substrings[i]);

    std::string plainText = getPlainText(substrings, cipherText.length(), keyLength);
    std::cout << "key= " << vigenereKey << "\n";
    return plainText;
}

/*
 * @Param:
 *      cipherText:   Reference to a Poly-alphabetic cipher text that we want to decrypt without knowing the encryption key
 * @Return:
 *      plainText:    Vector of possible deciphered texts
*/
std::vector<std::string> Vigenere(const std::string& cipherText)
{
    std::vector<std::string> plainTexts;
    std::vector<int> keyLengths;
    int bestLength = findLength(cipherText, keyLengths);

    if(bestLength == -1)
    {
        for(auto key: keyLengths){
            plainTexts.push_back(monoAlphabeticAttack(cipherText, key));
        }
    }
    else plainTexts.push_back(monoAlphabeticAttack(cipherText, bestLength));
    return plainTexts;
}

/*
 * @Param:
 *      inputString:    Reference to a string
 *      key_length:     Number of substrings that inputString will be split into
 * @Return:
 *      substrings:     Vector of strings; size = key_length
            substrings[i]: Every key_length characters of inputString starting from i
                            inputString[i + k * key_length]
*/
std::vector<std::string> getSubstrings(const std::string& inputString, const unsigned long key_length)
{
    std::vector<std::string> substrings;
    //substrings element that have a length longer of +1 compared to the rest of the elements
    unsigned long longerSubstrings = inputString.length() % key_length;
    unsigned long stringLength = inputString.length() / key_length;

    for (unsigned long i=0; i < longerSubstrings; ++i) substrings.push_back(std::string(stringLength+1,'c'));
    for (unsigned long i=longerSubstrings; i < key_length; ++i) substrings.push_back(std::string(stringLength, 'c'));

    for (int i=0; i < key_length; ++i)
    {
        int z=-1;
        for (int j=i; j < inputString.length(); j+=key_length)
            substrings[i][++z] = inputString[j];
    }

    return substrings;
}

/*
 * @Param:
 *      inputString:  Reference to a string text with characters only (if only lower case change 'A' to 'a')
 * @Return:
 *      frequencies:  Vector of double values; size = 26; frequencies[k] == probability of alphabet k in the inputString
*/
std::vector<double> getFrequencies(const std::string& inputString)
{
    std::vector<double> frequencies(26,0);

    unsigned long inputLength = inputString.length();
    for (int i = 0; i < inputLength; ++i) {
        frequencies[inputString[i] - 'A'] += 1;
    }
    for (int i = 0; i < 26; ++i) {
        frequencies[i] /= inputLength;
    }
    return frequencies;
}

/*
 * @Param:
 *      frequencies:            Vector of double values
 * @Return:
 *      squareFreqPermutation:  sum of P(k) * frequencies[ (k + shift) %26]; k:0->26 excluded
*/
std::vector<double> getSquareFreqPermutation(const std::vector<double>& frequencies)
{
    std::vector<double> squareFreqPermutation(26,0);
    for (int shift = 0; shift < 26; ++shift)
    {
        double sum(0);
        for (int j = 0; j < 26; ++j)
            sum += frequencies[(shift+j)%26] * english_probabilities[j];
        squareFreqPermutation[shift] = sum;
    }
    return squareFreqPermutation;
}

double getSumOfSquareProbabilities(std::vector<double>& probVec)
{
    double sum = 0;
    for(double val: probVec) sum += (val * val);
    return sum;
}

/*
 * @Param:
 *      inputValues:    Reference to a vector of double values
 *      target_value:   The value to find in the vector
 *      savedValue:     Pointer to a double value
 * @Return:
 *      index:          Index that points to the value that is closest to @target_value in the vector
 *      savedValue:     inputValues[index]
*/
int returnIndexClosestToValue(const std::vector<double>& inputValues, double target_value, double* savedValue)
{
    int index = 0 , i = 0;
    double best_prob(0);
    double epsilon = abs(target_value - inputValues[0]);
    for (double val : inputValues)
    {
        if (abs(target_value - val) < epsilon) {
            epsilon = abs(target_value - val);
            index = i;
            best_prob = val;
        }
        ++i;
    }
    if (savedValue != nullptr) *savedValue = best_prob;
    return index;
}

/*
 * @Param:
 *      cipherString:   Reference to a Mono-alphabetic cipher text (capital letters only)
 * @Return:
 *      cipherString:   Input deciphered
 *      key:            key used to decipher
*/
char attackCipherWithStatistics(std::string& cipherString)
{
    // 1. Get frequency of each letter
    std::vector<double> frequencies = getFrequencies(cipherString);

    // 2. Shift the frequencies to find the most likely permutation
    std::vector<double> squareFreqPermutation = getSquareFreqPermutation(frequencies);
    int best_shift = returnIndexClosestToValue(squareFreqPermutation, SQUARE_PROB_SUM);

    // 3. Decipher in place
    for (int i = 0; i < cipherString.length(); ++i) {
        cipherString[i]-= best_shift;

        if(cipherString[i] < 'A'){ //if we go below 'A' we need to subtract the difference from 'Z'+1
            cipherString[i] = 'Z' + (char)1 - ('A' - cipherString[i]);
        }
    }
    return (char)(best_shift + 'A');
}

/*
 * @Param:
 *      substrings:     Reference to vector of strings (deciphered)
 *      cipherLength:   length of the cipher text
 *      key_length:     key length of the Vigenere cipher
 * @Return:
 *      plaintext (rearrangement of the strings)
*/
std::string getPlainText(const std::vector<std::string>& substrings, const int cipherLength, const int key_length)
{
    unsigned long longerSubstrings = cipherLength % key_length;
    unsigned long subStringsSize = cipherLength / key_length; //size of substrings (except for the longer ones; that are size+1)

    std::string plainText(cipherLength, 'c');
    int index1 = 0; //index for plainText
    int index2 = 0; //index for the substrings
    for (; index2 < subStringsSize; ++index2)
    {
        for (int i = 0; i < key_length; ++i) {
            plainText[index1] = substrings[i][index2];
            ++index1;
        }
    }
    // last round for the longer substrings
    for (int i = 0; i < longerSubstrings; ++i) {
        plainText[index1] = substrings[i][index2];
        ++index1;
    }
    return plainText;
}

double abs(const double value){ return (value < 0) ? -value : value; }


/*
 * @Param:
 *      cipherText:   Reference to a poly-alphabetic cipher text whose key length we try to guess
 *      keyLengths:   Reference to an empty vector
 * @Return:
 *      keyLengths:   All possible key lengths
 *      GCD:          Greatest Common Divisor (this is the BEST possible key size); -1 if none
*/
int findLength(const std::string& cipherText, std::vector<int>& keyLengths)
{
    /*  find patterns and save distance between them
        get the divisors of those distances == possible key lengths
        find GCD
            if none return break it with stat
    */
    std::vector<int> distances = findPatternDistances(cipherText);
    for(auto dist : distances) addDivisors(dist,keyLengths);
    int GCD = findGCD(keyLengths);

    return GCD;
    // TODO can you have no divisors ? if so what happens to my program. can I return keyLength=0 ?

    /*
    if (GCD == 1) //maybe also GCD == 2
    {
        std::vector<double> bestSquareFreq;
        int keyLength(0);
        for (auto key_length : divisors) {
            std::vector<std::string> substrings = getSubstrings(cipherText, key_length);
            if (substrings[0].size() < MIN_NUMBER_CHARACTERS)
                continue;

            std::vector<double> squareFreq;
            for (std::string sub: substrings) {
                std::vector<double> frequencies = getFrequencies(sub);
                squareFreq.push_back(getSumOfSquareProbabilities(frequencies));
            }
            int bestIndex = returnIndexClosestToValue(squareFreq, SQUARE_PROB_SUM);
            bestSquareFreq.push_back(squareFreq[bestIndex]);
        }
        keyLength = returnIndexClosestToValue(bestSquareFreq, SQUARE_PROB_SUM);
        return keyLength;
    }
    else return GCD;
    */
}

/*
 * @Param:
 *      cipherText:  Reference to a poly-alphabetic cipher text in which we try to find repetition of strings
 * @Return:
 *      distances:   Vector of all distances found
*/
std::vector<int> findPatternDistances(const std::string& cipherText)
{
    std::vector<int> distances;
    int i(0);
    while (i < cipherText.length()-5)
    {
        std::string pattern(cipherText.substr(i, 3)); //if count == npos, the returned substring is [pos, size()).
        int patternSize = pattern.size();

        for (int j = i+3; j < cipherText.length();++j) {
            // TODO use compare method
            if(cipherText.substr(i, patternSize) == cipherText.substr(j, patternSize))
            {
                while(cipherText.substr(i, patternSize) == cipherText.substr(j, patternSize)){
                    ++patternSize;
                }
                --patternSize;
                pattern = cipherText.substr(i, patternSize);
                int diff = j-i;

                std::cout << "found the pattern " << pattern << "\n";
                std::cout << "distance= " << diff << "\n";
                distances.push_back(diff);
                j += patternSize-1;
            }
        }
        i += patternSize;
    }
    return distances;
}

/*
 * @Param:
 *      divisors:   Vector with divisors of one or more natural number
 * @Return:
 *      GCD:        Greatest Common Divisor between those numbers; -1 if none
*/
int findGCD(std::vector<int>& divisors)
{
    /* if divisors are unique then all Occurences are = 1
     * ==> we have to try all divisors
            return -1 to indicate this problem
    */
    // TODO add a filter to remove divisors that have occurences < Y (only when maxOccurences>1)

    std::sort (divisors.begin(), divisors.end());
    std::map<int,int> occurences;
    for (int i = 0; i < divisors.size(); ++i) {
        occurences[divisors[i]]+=1;
    }
    int maxOccurences(0), gcd(0);
    for (std::map<int,int>::iterator it=occurences.begin(); it!=occurences.end(); ++it){
        if (it->second > maxOccurences){
            maxOccurences = it->second;
            gcd = it->first;
        }
    }
    if(maxOccurences==1) return -1;
    else return gcd;
}

/*
 * @Param:
 *      n:          Positive natural number
 *      divisors:   Reference to an empty vector
 * @Return:
 *      divisors:   All divisors of n
*/
void addDivisors(const int n, std::vector<int>& divisors)
{
    for (int i = 2; i < n; ++i) {
        if(n%i == 0) divisors.push_back(i);
    }
}
