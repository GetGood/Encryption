#include <iostream>
#include <string>
#include <algorithm>

using namespace std;

string alphabet = "abcdefghijklmnopqrstuvwxyz";

string encode(string plaintext, int key) {
  string ciphertext = "";
  char c;
  // check if the character is alphabetic
  for (int i = 0; i < plaintext.size(); i++) {
    if (!isalpha(plaintext[i])) {
      ciphertext += plaintext[i];
    }
    // check if the character is uppercase
    else if (isupper(plaintext[i])) {
      c = tolower(plaintext[i]);
      // this is explained below
      c = alphabet[(alphabet.find(c)+key)%alphabet.size()];
      ciphertext += toupper(c);
    } else {
    // find index of character in alphabet, move that index
    // for the lenght of the key, use modulus operator in
    // case the lenght exceeds the lenght of alphabet
    ciphertext += alphabet[(alphabet.find(plaintext[i])+key)%alphabet.size()];
    }
  }
  return ciphertext;
}

string decode(string ciphertext, int key) {
  string plaintext = "";
  char c;
  // check if the character is alphabetic
  for (int i = 0; i < ciphertext.size(); i++) {
    if (!isalpha(ciphertext[i])) {
      plaintext += ciphertext[i];
    }
    // check if the character is uppercase
    else if (isupper(ciphertext[i])) {
      c = tolower(ciphertext[i]);
      // this is explained below
      c = alphabet[(alphabet.find(c)+(alphabet.size()-key))%alphabet.size()];
      plaintext += toupper(c);
    } else {
      // find the index of the encryted character in alphabet, move forward
      // 26-key indexes. use modulus operator if the key exeeds the lenght of
      // the alphabet size (start over from index 0)
    plaintext += alphabet[(alphabet.find(ciphertext[i])+(alphabet.size()
    -key))%alphabet.size()];
    }
  }
  return plaintext;
}

//function for bruteforcing every possible key with the option
//to recognize the right pattern using a keyword that should
//occur in the string
void bruteforce(string ciphertext, int key, string keyword) {
  string teststring, lowcharstring;
  cout << "keyword is: " << keyword << endl;
  if(keyword == "") {
    for(key; key < alphabet.size(); key++) {
      cout << "key " << key << ": " << encode(ciphertext, key) << endl;
    }
  } else {
    for(key; key < alphabet.size(); key++) {
      teststring = encode(ciphertext, key);
      lowcharstring = teststring;
      // since the keyword is low characters we need to
      // temporarily transform the inspected string to
      // low characters.
      transform(lowcharstring.begin(), lowcharstring.end(),
      lowcharstring.begin(), ::tolower);
      if (lowcharstring.find(keyword) != string::npos) {
        cout << "found string containing keyword: " << teststring << endl;
        cout << "with key " << key << endl;
      }
    }
  }
}

int main() {
  int key = 0;
  string plaintext, ciphertext, keyword;
  char option;
  cout << "select function(e:encrypt d:decrypt b:bruteforce): ";
  cin >> option;
  switch(option) {
    case 'e' :
      cout << "Insert k for Caesar Encrypt: ";
      cin >> key;
      cout << "Insert plaintext for Caesar Encrypt: ";
      cin.ignore();
      getline(cin, plaintext);
      cout << encode(plaintext, key) << endl;
      break;
    case 'd' :
      cout << "Insert k for Caesar Decrypt: ";
      cin >> key;
      cout << "Insert ciphertext for Caesar Decrypt: ";
      cin.ignore();
      getline(cin, ciphertext);
      cout << decode(ciphertext, key) << endl;
      break;
    case 'b' :
      cout << "Insert keyword for bruteforce(optional):";
      cin.ignore();
      getline(cin, keyword);
      cout << "Insert ciphertext for Bruteforce: ";
      getline(cin, ciphertext);
      bruteforce(ciphertext, key, keyword);
      break;
    default :
      cout << "Invalid option" << endl;
      break;
  }
  return(0);
}
