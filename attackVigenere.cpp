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

    findLength(cipherLength5);
/*
    std::string plaintext;
    //attackCipherWithStatistics(cipherLength1);
    plaintext = Vigenere(cipherLength1);
    std::cout << plaintext << "\n";

    plaintext = Vigenere(cipherLength5);
    std::cout << plaintext << "\n";

    plaintext = Vigenere(plaintext2);
    std::cout << plaintext << "\n";
*/

    return 0;
}


// Decrypt Vigenere with unknown key-length
std::string Vigenere(std::string cipherText) {
    int key_length = MIN_KEY_LENGTH;

    // A. Find key-length in the range MIN to MAX KEY_LENGTH
    {
        std::vector<double> bestSquareFreq;
        for (; key_length <= MAX_KEY_LENGTH; ++key_length)
        {
            std::vector<std::string> substrings = getSubstrings(cipherText, key_length);
            if (substrings[0].size() < MIN_NUMBER_CHARACTERS)
                continue;

            std::vector<double> squareFreq;
            for (std::string sub: substrings)
            {
                std::vector<double> frequencies = getFrequencies(sub);
                squareFreq.push_back(getSumOfSquareProbabilities(frequencies));
            }
            int bestIndex = returnIndexClosestToValue(squareFreq, SQUARE_PROB_SUM);
            bestSquareFreq.push_back(squareFreq[bestIndex]);
        }
        key_length = MIN_KEY_LENGTH + returnIndexClosestToValue(bestSquareFreq, SQUARE_PROB_SUM);
    }

    // B. Decrypt Vigenere with known key-length
    std::vector<std::string> substrings = getSubstrings(cipherText, key_length);
    std::string vigenereKey(key_length,'-');
    for (int i=0; i < key_length; ++i)
        vigenereKey[i] = attackCipherWithStatistics(substrings[i]);

    // C. Combine substrings to get plaintext
    std::string plainText = getPlainText(substrings, cipherText.length(), key_length);
    std::cout << "key= " << vigenereKey << "\n";
    return plainText;
}

/*
 * @Param:
 *      cipherText: cipher Text to rearrange into 'length' alphabets
 *      key_length:     key length of the Vigenere cipher
 * @Return:
 *      array[key_length]
            array[i]: string of characters cypherText[i + k * key_length]
*/
std::vector<std::string> getSubstrings(const std::string& cipherText, unsigned long key_length)
{
    std::vector<std::string> substrings;

    unsigned long longerSubstrings = cipherText.length() % key_length; //substrings element that have a length longer of +1 compared to the rest of the elements
    unsigned long stringLength = cipherText.length() / key_length;

    for (unsigned long i=0; i < longerSubstrings; ++i) substrings.push_back(std::string(stringLength+1,'c'));
    for (unsigned long i=longerSubstrings; i < key_length; ++i) substrings.push_back(std::string(stringLength, 'c'));

    for (int i=0; i < key_length; ++i)
    {
        int z=-1;
        for (int j=i; j<cipherText.length(); j+=key_length)
            substrings[i][++z] = cipherText[j];
    }

    return substrings;
}

/*
 * @Param:
 *      cipherText: cipher Text with only upper case characters (if only upper case change 'A' to 'a'
 * @Return:
 *      frequencies[26]; probability of alphabet k in the cipherText
*/
std::vector<double> getFrequencies(const std::string& cipherString)
{
    std::vector<double> frequencies(26,0);

    unsigned long cipherLength = cipherString.length();
    for (int i = 0; i < cipherLength; ++i) {
        frequencies[cipherString[i] - 'A'] += 1;
    }
    for (int i = 0; i < 26; ++i) {
        frequencies[i] /= cipherLength;
    }
    return frequencies;
}

std::vector<double> getSquareFreqPermutation(std::vector<double>& frequencies)
{
    std::vector<double> squareFreqPermutation(26,0);
    for (int shift = 0; shift < 26; ++shift) {
        double sum(0);
        for (int j = 0; j < 26; ++j) {
            sum += frequencies[(shift+j)%26] * english_probabilities[j];
        }
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
 *      allSquareProbabilities = vector of J where J is the sum of the square of probabilities
 *      value = the value that we want to find in our vector
 *      squareProbToSave = double pointer
 * @Return:
 *      index: the index in the vector whose value is closest to @target_value
 *      squareProbToSave: allSquareProbabilities[index]
*/
int returnIndexClosestToValue(std::vector<double> allSquareProbabilities, double target_value, double* squareProbToSave)
{
    int index = 0 , i = 0;
    double best_prob(0);
    double epsilon = abs(target_value - allSquareProbabilities[0]);
    for (double val : allSquareProbabilities)
    {
        if (abs(target_value - val) < epsilon) {
            epsilon = abs(target_value - val);
            index = i;
            best_prob = val;
        }
        ++i;
    }
    if (squareProbToSave!= nullptr) *squareProbToSave = best_prob;
    return index;
}

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
 *      substrings:     vector of strings (deciphered)
 *      cipherLength:   length of the cipher text
 *      key_length:     key length of the Vigenere cipher
 * @Return:
 *      plaintext (rearrangement of the strings)
*/
std::string getPlainText(std::vector<std::string>& substrings, int cipherLength, int key_length)
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

double abs(double value){
    return (value < 0) ? -value : value;
}

std::vector<int> findPatternDistances(std::string& cipherText)
{
    std::vector<int> distances;
    int i(0);
    while (i < cipherText.length()-5)
    {
        std::string pattern(cipherText.substr(i, 3)); //if count == npos, the returned substring is [pos, size()).
        int patternSize = pattern.size();

        for (int j = i+3; j < cipherText.length();++j) {
            // would be nice to use compare method
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
}

int findLength(std::string& cipherText)
{
    /*  find patterns and save distance between them
        get the divisors of those distances
        find GCD
            if ties break it with stat
    */
    std::vector<int> distances = findPatternDistances(cipherText);
    std::vector<int> divisors;
    for(auto dist : distances) addDivisors(dist,divisors);
    int GCD = findGCD(divisors);

    if (GCD == 1)
    {
        return 1;
    }
    else return GCD;
}

int findGCD(std::vector<int>& divisors)
{
    /* if divisors are unique then all Occurences are = 1
     * ==> we have to try all divisors
            return 1 to indicate this problem
            then take the vector and apply stat to each of the divisors
    */

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
    if(maxOccurences==1) return 1;
    return gcd;
}

void addDivisors(int n, std::vector<int>& divisors)
{
    for (int i = 2; i < n; ++i) {
        if(n%i == 0) divisors.push_back(i);
    }
}
