/*
Aaron Richardson
Intoduction to Cryptology - CPSC 370 - 1:45pm
arichard13@live.esu.edu
The purpose of this program is to encrypt and decrypt 16-bit plaintext
using S-AES and implement differential cryptanalysis for 1 round S-AES. 
We are given the plaintext and key.
*/

#include <iostream>
#include <string>
#include <bitset>

using namespace std;

string Sbox(string s);
string InvSbox(string s);
string MulTable(string s);

void KeyExpansion(bitset<16> key);
bitset<8> SubNib(bitset<8> sub);
bitset<8> RotNib(bitset<8> rot);
bitset<16> k1;
bitset<16> k2;

bitset<16> AddRoundKey(bitset<16> a, bitset<16> b);
bitset<16> ShiftRow(bitset<16> rows);
bitset<16> NibSub(bitset<16> n);
bitset<16> InvNibSub(bitset<16> n);
bitset<16> MixColumn(bitset<16> x);
bitset<16> InvMixColumn(bitset<16> x);

bitset<4> xSqNib1;
bitset<4> xSqNib2;
bitset<4> xSqNib3;
bitset<4> xSqNib4;

bitset<4> Cryptanalysis(bitset<4> pNib1, bitset<4> pNib2, bitset<4> pNib3, bitset<4> pNib4, bitset<4> cNib1, bitset<4> cNib2, bitset<4> cNib3, bitset<4> cNib4);
bitset<4> stringToBitset(string str);

bitset<16> plaintext("0110111101101011"); // ASCII = ok
bitset<16> k0("1010011100111011");

int main()
{
	KeyExpansion(k0);
	bitset<16> temp;

	cout << "The following program will encrypt and decrypt using S-AES.\n\n";

	cout << "Plaintext: " << plaintext << endl;
	cout << "Key: " << k0 << endl;

	cout << "\n\n====================================================\n";
	cout << "                Encryption: Round 0\n";
	cout << "====================================================\n\n";
	
	cout << "AddRoundKey(): " << AddRoundKey(plaintext, k0);

	cout << "\n\n====================================================\n";
	cout << "                Encryption: Round 1\n";
	cout << "====================================================\n\n";

	cout << "NibSub(): " << NibSub(AddRoundKey(plaintext, k0)) << endl;
	cout << "ShiftRow(): " << ShiftRow(NibSub(AddRoundKey(plaintext, k0))) << endl;
	cout << "MixColumn(): " << MixColumn(ShiftRow(NibSub(AddRoundKey(plaintext, k0)))) << endl;
	cout << "AddRoundKey(): " << AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(plaintext, k0)))), k1) << endl;
	temp = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(plaintext, k0)))), k1);

	cout << "\n\n====================================================\n";
	cout << "                Encryption: Round 2\n";
	cout << "====================================================\n\n";

	cout << "NibSub(): " << NibSub(temp) << endl;
	cout << "ShiftRow(): " << ShiftRow(NibSub(temp)) << endl;
	cout << "AddRoundKey(): " << AddRoundKey(ShiftRow(NibSub(temp)), k2) << endl << endl;

	bitset<16> ciphertext = AddRoundKey(ShiftRow(NibSub(temp)), k2);
	cout << "****** Ciphertext: " << ciphertext << " ******\n";

	cout << "\n\n====================================================\n";
	cout << "                Decryption: Round 2\n";
	cout << "====================================================\n\n";

	cout << "AddRoundKey(): " << AddRoundKey(ciphertext, k2) << endl;
	cout << "ShiftRow(): " << ShiftRow(AddRoundKey(ciphertext, k2)) << endl;
	cout << "InvNibSub(): " << InvNibSub(ShiftRow(AddRoundKey(ciphertext, k2))) << endl;
	temp = InvNibSub(ShiftRow(AddRoundKey(ciphertext, k2)));

	cout << "\n\n====================================================\n";
	cout << "                Decryption: Round 1\n";
	cout << "====================================================\n\n";

	cout << "AddRoundKey(): " << AddRoundKey(temp, k1) << endl;
	cout << "InvMixColumn(): " << InvMixColumn(AddRoundKey(temp, k1)) << endl;
	cout << "ShiftRow(): " << ShiftRow(InvMixColumn(AddRoundKey(temp, k1))) << endl;
	cout << "InvNibSub(): " << InvNibSub(ShiftRow(InvMixColumn(AddRoundKey(temp, k1)))) << endl;
	temp = InvNibSub(ShiftRow(InvMixColumn(AddRoundKey(temp, k1))));

	cout << "\n\n====================================================\n";
	cout << "                Decryption: Round 0\n";
	cout << "====================================================\n\n";

	cout << "AddRoundKey(): " << AddRoundKey(temp, k0) << endl << endl;
	cout << "****** Plaintext: " << AddRoundKey(temp, k0) << " ******\n\n";

	
	/////////////////////////////////////////////////////////////////////
	///////				Differential Cryptanalysis				   //////
	/////////////////////////////////////////////////////////////////////
	cout << "\n\n====================================================\n";
	cout << "         Differential Cryptanalysis Example:\n";
	cout << "====================================================\n\n";

	bitset<16> No("0100111001101111"); // ASCII = No
	bitset<16> KEY("1101110011101111");
	KeyExpansion(KEY);

	cout << "We encrypt the plaintext " << No <<  " (No)\n";

	AddRoundKey(No, KEY);
	NibSub(AddRoundKey(No, KEY));
	ShiftRow(NibSub(AddRoundKey(No, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(No, KEY))));
	bitset<16> ciph_No = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(No, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_No << endl << endl;

	bitset<16> to("0111010001101111"); // ASCII = to
	cout << "We encrypt the plaintext " << to << " (to)\n";

	AddRoundKey(to, KEY);
	NibSub(AddRoundKey(to, KEY));
	ShiftRow(NibSub(AddRoundKey(to, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(to, KEY))));
	bitset<16> ciph_to = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(to, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_to << endl << endl;

	bitset<16> Mr("0100110101110010"); // ASCII = Mr
	cout << "We encrypt the plaintext " << Mr << " (Mr)\n";

	AddRoundKey(Mr, KEY);
	NibSub(AddRoundKey(Mr, KEY));
	ShiftRow(NibSub(AddRoundKey(Mr, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(Mr, KEY))));
	bitset<16> ciph_Mr = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(Mr, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_Mr << endl << endl;

	bitset<16> or_("0110111101110010"); // ASCII = or
	cout << "We encrypt the plaintext " << or_ << " (or)\n";

	AddRoundKey(or_, KEY);
	NibSub(AddRoundKey(or_, KEY));
	ShiftRow(NibSub(AddRoundKey(or_, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(or_, KEY))));
	bitset<16> ciph_or = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(or_, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_or << endl << endl;

	bitset<16> if_("0110100101100110"); // ASCII = if
	cout << "We encrypt the plaintext " << if_ << " (if)\n";

	AddRoundKey(if_, KEY);
	NibSub(AddRoundKey(if_, KEY));
	ShiftRow(NibSub(AddRoundKey(if_, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(if_, KEY))));
	bitset<16> ciph_if = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(if_, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_if << endl << endl;

	bitset<16> is("0110100101110011"); // ASCII = is
	cout << "We encrypt the plaintext " << is << " (is)\n";

	AddRoundKey(is, KEY);
	NibSub(AddRoundKey(is, KEY));
	ShiftRow(NibSub(AddRoundKey(is, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(is, KEY))));
	bitset<16> ciph_is = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(is, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_is << endl << endl;

	bitset<16> PM("0101000001001101"); // ASCII = PM
	cout << "We encrypt the plaintext " << PM << " (PM)\n";

	AddRoundKey(PM, KEY);
	NibSub(AddRoundKey(PM, KEY));
	ShiftRow(NibSub(AddRoundKey(PM, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(PM, KEY))));
	bitset<16> ciph_PM = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(PM, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_PM << endl << endl;

	bitset<16> Pa("0101000001100001"); // Pa
	cout << "We encrypt the plaintext " << Pa << " (Pa)\n";

	AddRoundKey(Pa, KEY);
	NibSub(AddRoundKey(Pa, KEY));
	ShiftRow(NibSub(AddRoundKey(Pa, KEY)));
	MixColumn(ShiftRow(NibSub(AddRoundKey(Pa, KEY))));
	bitset<16> ciph_Pa = AddRoundKey(MixColumn(ShiftRow(NibSub(AddRoundKey(Pa, KEY)))), k1);

	cout << "and after 1 round we get " << ciph_Pa << endl << endl;
	
	// splits "No" set into four nibbles
	int j = 0;
	bitset<4> NoNib1, NoNib2, NoNib3, NoNib4;
	for (int i = 12; i < 16; i++) {
		NoNib1[j] = No[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		NoNib2[j] = No[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		NoNib3[j] = No[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		NoNib4[i] = No[i];
	}
	// splits "to" into four nibbles
	bitset<4> toNib1, toNib2, toNib3, toNib4;
	for (int i = 12; i < 16; i++) {
		toNib1[j] = to[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		toNib2[j] = to[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		toNib3[j] = to[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		toNib4[i] = to[i];
	}
	// splits "Mr" into four nibbles
	bitset<4> MrNib1, MrNib2, MrNib3, MrNib4;
	for (int i = 12; i < 16; i++) {
		MrNib1[j] = Mr[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		MrNib2[j] = Mr[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		MrNib3[j] = Mr[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		MrNib4[i] = Mr[i];
	}
	// splits "or" into four nibbles
	bitset<4> or_Nib1, or_Nib2, or_Nib3, or_Nib4;
	for (int i = 12; i < 16; i++) {
		or_Nib1[j] = or_[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		or_Nib2[j] = or_[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		or_Nib3[j] = or_[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		or_Nib4[i] = or_[i];
	}
	// splits "if" into four nibbles
	bitset<4> if_Nib1, if_Nib2, if_Nib3, if_Nib4;
	for (int i = 12; i < 16; i++) {
		if_Nib1[j] = if_[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		if_Nib2[j] = if_[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		if_Nib3[j] = if_[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		if_Nib4[i] = if_[i];
	}
	// splits "is" into four nibbles
	bitset<4> isNib1, isNib2, isNib3, isNib4;
	for (int i = 12; i < 16; i++) {
		isNib1[j] = is[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		isNib2[j] = is[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		isNib3[j] = is[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		isNib4[i] = is[i];
	}
	// splits "PM" into four nibbles
	bitset<4> PMnib1, PMnib2, PMnib3, PMnib4;
	for (int i = 12; i < 16; i++) {
		PMnib1[j] = PM[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		PMnib2[j] = PM[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		PMnib3[j] = PM[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		PMnib4[i] = PM[i];
	}
	// splits "Pa" into four nibbles
	bitset<4> PaNib1, PaNib2, PaNib3, PaNib4;
	for (int i = 12; i < 16; i++) {
		PaNib1[j] = Pa[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		PaNib2[j] = Pa[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		PaNib3[j] = Pa[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		PaNib4[i] = Pa[i];
	}
	// splits ciph_No into four nibbles
	bitset<4> cNoNib1, cNoNib2, cNoNib3, cNoNib4;
	for (int i = 12; i < 16; i++) {
		cNoNib1[j] = ciph_No[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		cNoNib2[j] = ciph_No[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		cNoNib3[j] = ciph_No[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		cNoNib4[i] = ciph_No[i];
	}
	// splits ciph_to into four nibbles
	bitset<4> ctoNib1, ctoNib2, ctoNib3, ctoNib4;
	for (int i = 12; i < 16; i++) {
		ctoNib1[j] = ciph_to[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		ctoNib2[j] = ciph_to[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		ctoNib3[j] = ciph_to[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		ctoNib4[i] = ciph_to[i];
	}
	// splits ciph_Mr into four nibbles
	bitset<4> cMrNib1, cMrNib2, cMrNib3, cMrNib4;
	for (int i = 12; i < 16; i++) {
		cMrNib1[j] = ciph_Mr[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		cMrNib2[j] = ciph_Mr[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		cMrNib3[j] = ciph_Mr[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		cMrNib4[i] = ciph_Mr[i];
	}
	// splits ciph_or into four nibbles
	bitset<4> corNib1, corNib2, corNib3, corNib4;
	for (int i = 12; i < 16; i++) {
		corNib1[j] = ciph_or[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		corNib2[j] = ciph_or[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		corNib3[j] = ciph_or[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		corNib4[i] = ciph_or[i];
	}
	// splits ciph_if into four nibbles
	bitset<4> cifNib1, cifNib2, cifNib3, cifNib4;
	for (int i = 12; i < 16; i++) {
		cifNib1[j] = ciph_if[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		cifNib2[j] = ciph_if[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		cifNib3[j] = ciph_if[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		cifNib4[i] = ciph_if[i];
	}
	// splits ciph_is into four nibbles
	bitset<4> cisNib1, cisNib2, cisNib3, cisNib4;
	for (int i = 12; i < 16; i++) {
		cisNib1[j] = ciph_is[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		cisNib2[j] = ciph_is[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		cisNib3[j] = ciph_is[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		cisNib4[i] = ciph_is[i];
	}
	// splits ciph_PM into four nibbles
	bitset<4> cPMnib1, cPMnib2, cPMnib3, cPMnib4;
	for (int i = 12; i < 16; i++) {
		cPMnib1[j] = ciph_PM[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		cPMnib2[j] = ciph_PM[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		cPMnib3[j] = ciph_PM[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		cPMnib4[i] = ciph_PM[i];
	}
	// splits ciph_Pa into four nibbles
	bitset<4> cPaNib1, cPaNib2, cPaNib3, cPaNib4;
	for (int i = 12; i < 16; i++) {
		cPaNib1[j] = ciph_Pa[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		cPaNib2[j] = ciph_Pa[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		cPaNib3[j] = ciph_Pa[i];
		j++;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		cPaNib4[i] = ciph_Pa[i];
	}
	cout << "Key used: " << KEY << endl;
	cout << "\nAfter performing differential cryptanalysis:\n";

	bitset<4> keyNib1 = Cryptanalysis(NoNib1, toNib1, MrNib1, or_Nib1, cNoNib1, ctoNib1, cMrNib1, corNib1);
	cout << "Equation I\n" << keyNib1 << endl;

	bitset<4> keyNib2 = Cryptanalysis(NoNib2, toNib2, MrNib2, or_Nib2, cNoNib4, ctoNib4, cMrNib4, corNib4);
	cout << "Equation II\n" << keyNib2 << endl;

	bitset<4> keyNib3 = Cryptanalysis(if_Nib3, isNib3, PMnib3, PaNib3, cifNib3, cisNib3, cPMnib3, cPaNib3);
	cout << "Equation III\n" << keyNib3 << endl;
	
	bitset<4> keyNib4 = Cryptanalysis(if_Nib4, isNib4, PMnib4, PaNib4, cifNib2, cisNib2, cPMnib2, cPaNib2);
	cout << "Equation IV\n" << keyNib4 << endl;


	system("pause");
	return 0;
}
bitset<4> stringToBitset(string str)
{
	bitset<4> bits(str);
	return bits;
}
bitset<4> Cryptanalysis(bitset<4> pNib1, bitset<4> pNib2, bitset<4> pNib3, bitset<4> pNib4, bitset<4> cNib1, bitset<4> cNib2, bitset<4> cNib3, bitset<4> cNib4)
{
	bitset<4> SboxResult1, SboxResult2, SboxResult3, SboxResult4;
	bitset<4> testKeyNib;
	bitset<4> x1, y1, z1, a1;
	bitset<4> x2, y2, z2, a2;
	
	a1 = cNib1 ^ cNib2;
	a2 = cNib3 ^ cNib4;
	for (int i = 0; i < 16; i++)
	{
		testKeyNib = i;

		x1 = pNib1 ^ testKeyNib;
		y1 = pNib2 ^ testKeyNib;
		x2 = pNib3 ^ testKeyNib;
		y2 = pNib4 ^ testKeyNib;

		// performs S-box substitution
		SboxResult1 = stringToBitset(Sbox(x1.to_string()));
		SboxResult2 = stringToBitset(Sbox(y1.to_string()));
		SboxResult3 = stringToBitset(Sbox(x2.to_string()));
		SboxResult4 = stringToBitset(Sbox(y2.to_string()));
		
		z1 = SboxResult1 ^ SboxResult2;
		z2 = SboxResult3 ^ SboxResult4;

		if (a1 == z1 && a2 == z2)
			break;
	}
	return testKeyNib;
}
void KeyExpansion(bitset<16> key)
{
	bitset<8> Rcon1("10000000"); // constant 1
	bitset<8> Rcon2("00110000"); // constant 2
	bitset<8> w0, w1, w2, w3, w4, w5;
	int j = 0;

	// splits set into w0 and w1
	for (int i = 8; i < 16; i++) {
		w0[j] = key[i];
		j++;
	}
	for (int i = 0; i < 8; i++) {
		w1[i] = key[i];
	}

	w2 = w0 ^ Rcon1 ^ SubNib(RotNib(w1));
	w3 = w2 ^ w1;
	w4 = w2 ^ Rcon2 ^ SubNib(RotNib(w3));
	w5 = w4 ^ w3;

	j = 0;
	for (int i = 8; i < 16; i++) {
		k1[i] = w2[j];
		j++;
	}
	for (int i = 0; i < 8; i++) {
		k1[i] = w3[i];
	}
	j = 0;
	for (int i = 8; i < 16; i++) {
		k2[i] = w4[j];
		j++;
	}
	for (int i = 0; i < 8; i++) {
		k2[i] = w5[i];
	}
}
bitset<8> SubNib(bitset<8> sub)
{
	bitset<4> sub1, sub2;
	int j = 0;
	for (int i = 4; i < 8; i++) {
		sub1[j] = sub[i];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		sub2[i] = sub[i];
	}
	// convert bitset to string
	string s1 = sub1.to_string();
	string s2 = sub2.to_string();

	// combines nibble strings
	string nibbleString = Sbox(s1) + Sbox(s2);

	// converts string to bitset
	bitset<8> subbed(nibbleString);
	
	return subbed;
}
bitset<8> RotNib(bitset<8> rot)
{
	bitset<8> rotated;
	int j = 0;
	for (int i = 4; i < 8; i++) {
		rotated[j] = rot[i];
		j++;
	}
	j = 4;
	for (int i = 0; i < 4; i++) {
		rotated[j] = rot[i];
		j++;
	}
	return rotated;
}
bitset<16> AddRoundKey(bitset<16> a, bitset<16> b)
{
	return a ^= b;
}
bitset<16> ShiftRow(bitset<16> rows)
{
	bitset<16> shifted;
	int j = 0;

	// shifts
	for (int i = 12; i < 16; i++) {
		shifted[i] = rows[i];
	}
	for (int i = 8; i < 12; i++) {
		shifted[j] = rows[i];
		j++;
	}
	for (int i = 4; i < 8; i++) {
		shifted[i] = rows[i];
	}
	j = 8;
	for (int i = 0; i < 4; i++) {
		shifted[j] = rows[i];
		j++;
	}
	return shifted;
}
bitset<16> MixColumn(bitset<16> x)
{
	bitset<4> nib1, nib2, nib3, nib4;
	int j = 0;

	// splits set into four nibbles
	for (int i = 12; i < 16; i++) {
		nib1[j] = x[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		nib2[j] = x[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		nib3[j] = x[i];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		nib4[i] = x[i];
	}
	// generates bitsets of the correct product
	bitset<4> xSq1(MulTable(nib1.to_string()));
	bitset<4> xSq2(MulTable(nib2.to_string()));
	bitset<4> xSq3(MulTable(nib3.to_string()));
	bitset<4> xSq4(MulTable(nib4.to_string()));

	xSqNib1 = xSq1;
	xSqNib2 = xSq2;
	xSqNib3 = xSq3;
	xSqNib4 = xSq4;
	// XOR
	nib1 ^= xSqNib2;
	nib2 ^= xSqNib1;
	nib3 ^= xSqNib4;
	nib4 ^= xSqNib3;

	bitset<16> mixed;

	// combines the four nibbles
	j = 0;
	for (int i = 12; i < 16; i++) {
		mixed[i] = nib1[j];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		mixed[i] = nib2[j];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		mixed[i] = nib3[j];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		mixed[i] = nib4[i];
	}
	return mixed;
}
bitset<16> NibSub(bitset<16> n)
{
	bitset<4> nib1, nib2, nib3, nib4;
	int j = 0;

	// splits set into four nibbles
	for (int i = 12; i < 16; i++) {
		nib1[j] = n[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		nib2[j] = n[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		nib3[j] = n[i];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		nib4[i] = n[i];
	}
	// convert bitset to string
	string s1 = nib1.to_string();
	string s2 = nib2.to_string();
	string s3 = nib3.to_string();
	string s4 = nib4.to_string();

	// combines nibble strings
	string nibbleString = Sbox(s1) + Sbox(s2) + Sbox(s3) + Sbox(s4);

	// converts string to bitset
	bitset<16> nibbles(nibbleString);

	return nibbles;
}
bitset<16> InvMixColumn(bitset<16> x)
{
	bitset<4> nib1, nib2, nib3, nib4;
	int j = 0;

	// splits set into four nibbles
	for (int i = 12; i < 16; i++) {
		nib1[j] = x[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		nib2[j] = x[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		nib3[j] = x[i];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		nib4[i] = x[i];
	}
	// XOR
	nib1 ^= xSqNib2;
	nib2 ^= xSqNib1;
	nib3 ^= xSqNib4;
	nib4 ^= xSqNib3;

	bitset<16> mixed;

	// combines the four nibbles
	j = 0;
	for (int i = 12; i < 16; i++) {
		mixed[i] = nib1[j];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		mixed[i] = nib2[j];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		mixed[i] = nib3[j];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		mixed[i] = nib4[i];
	}
	return mixed;
}
bitset<16> InvNibSub(bitset<16> n)
{
	bitset<4> nib1, nib2, nib3, nib4;
	int j = 0;

	// splits set into four nibbles
	for (int i = 12; i < 16; i++) {
		nib1[j] = n[i];
		j++;
	}
	j = 0;
	for (int i = 8; i < 12; i++) {
		nib2[j] = n[i];
		j++;
	}
	j = 0;
	for (int i = 4; i < 8; i++) {
		nib3[j] = n[i];
		j++;
	}
	for (int i = 0; i < 4; i++) {
		nib4[i] = n[i];
	}
	// convert bitset to string
	string s1 = nib1.to_string();
	string s2 = nib2.to_string();
	string s3 = nib3.to_string();
	string s4 = nib4.to_string();

	// combines nibble strings
	string nibbleString = InvSbox(s1) + InvSbox(s2) + InvSbox(s3) + InvSbox(s4);

	// converts string to bitset
	bitset<16> nibbles(nibbleString);

	return nibbles;
}
string Sbox(string s)
{
	if (s == "0000") {
		s = "1001";
	}
	else if (s == "0001") {
		s = "0100";
	}
	else if (s == "0010") {
		s = "1010";
	}
	else if (s == "0011") {
		s = "1011";
	}
	else if (s == "0100") {
		s = "1101";
	}
	else if (s == "0101") {
		s = "0001";
	}
	else if (s == "0110") {
		s = "1000";
	}
	else if (s == "0111") {
		s = "0101";
	}
	else if (s == "1000") {
		s = "0110";
	}
	else if (s == "1001") {
		s = "0010";
	}
	else if (s == "1010") {
		s = "0000";
	}
	else if (s == "1011") {
		s = "0011";
	}
	else if (s == "1100") {
		s = "1100";
	}
	else if (s == "1101") {
		s = "1110";
	}
	else if (s == "1110") {
		s = "1111";
	}
	else {
		s = "0111";
	}
	return s;
}
string InvSbox(string s)
{
	if (s == "1001") {
		s = "0000";
	}
	else if (s == "0100") {
		s = "0001";
	}
	else if (s == "1010") {
		s = "0010";
	}
	else if (s == "1011") {
		s = "0011";
	}
	else if (s == "1101") {
		s = "0100";
	}
	else if (s == "0001") {
		s = "0101";
	}
	else if (s == "1000") {
		s = "0110";
	}
	else if (s == "0101") {
		s = "0111";
	}
	else if (s == "0110") {
		s = "1000";
	}
	else if (s == "0010") {
		s = "1001";
	}
	else if (s == "0000") {
		s = "1010";
	}
	else if (s == "0011") {
		s = "1011";
	}
	else if (s == "1100") {
		s = "1100";
	}
	else if (s == "1110") {
		s = "1101";
	}
	else if (s == "1111") {
		s = "1110";
	}
	else {
		s = "1111";
	}
	return s;
}
string MulTable(string s)
{
	if (s == "0000") {
		s = "0000";
	}
	else if (s == "0001") {
		s = "0100";
	}
	else if (s == "0010") {
		s = "1000";
	}
	else if (s == "0011") {
		s = "1100";
	}
	else if (s == "0100") {
		s = "0011";
	}
	else if (s == "0101") {
		s = "0111";
	}
	else if (s == "0110") {
		s = "1011";
	}
	else if (s == "0111") {
		s = "1111";
	}
	else if (s == "1000") {
		s = "0110";
	}
	else if (s == "1001") {
		s = "0010";
	}
	else if (s == "1010") {
		s = "1110";
	}
	else if (s == "1011") {
		s = "1010";
	}
	else if (s == "1100") {
		s = "0101";
	}
	else if (s == "1101") {
		s = "0001";
	}
	else if (s == "1110") {
		s = "1101";
	}
	else {
		s = "1001";
	}
	return s;
}