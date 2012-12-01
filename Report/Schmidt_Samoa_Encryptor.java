package com.jinkchak;

import java.security.InvalidAlgorithmParameterException;

import org.eclipse.swt.widgets.Display;

public class Schmidt_Samoa_Encryptor {
	private int p, q;
	private int public_key, private_key;
	
	private static final int BLOCK_SIZE = 6;			//For splitting a String of text into blocks
	
	/**
	 * This constructor initializes the following variables:
	 * 		p - with a default value of 23
	 * 		q - with a default value of 31
	 * After that, it calls a method that computes the private and public keys
	 * 
	 */
	public Schmidt_Samoa_Encryptor()
	{
		reInitialize(23, 31);	
	}
	
	/**
	 * Re-initializes the system with the new values for p and q, and then
	 * computes the new values of the public and private keys.
	 * @param p A large prime number
	 * @param q A large prime number that is distinct from q 
	 * 
	 */
	public void reInitialize(int p, int q)
	{
		this.p = p;
		this.q = q;
		public_key = computeN();
		try {
			private_key = modular_Equation_Solver(public_key, 1, lcm(p-1, q-1));
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Computes the lcm of two integers
	 * @param a An integer
	 * @param b An integer
	 * @return LCM of a and b
	 */
	private int lcm(int a, int b)
	{
		return (a*b)/gcd(a,b);
	}
	
	/**
	 * Computes the GCD of two integers
	 * @param a An integer
	 * @param b An integer
	 * @return GCD of a and b
	 */
	private int gcd(int a, int b) {
		if (b==0)
			return a;
		return gcd(b,a%b);
	}
	
	/**This method contains an implementation of the extended Euclidean algorithm.
	 * The extended Euclidean algorithm is an extension to the Euclidean algorithm. 
	 * Besides finding the greatest common divisor of two integers, as the Euclidean algorithm does, 
	 * it also finds integers x and y (one of which is typically negative) that satisfy Bézout's identity:
	 * 			ax + by = gcd(a, b)
	 * @param a An integer
	 * @param b An integer
	 * @return An integer array z consisting of three element:
	 * 			z[0] = gcd(a, b)
	 * 			z[1] = x
	 * 			z[2] = y
	 */
	private int[] extendedEuclidsAlgo(int a, int b)
	{
		int []result = new int[3];
		if(b==0)
		{
			result[0] = a;// index 0 is x
			result[1] = 1;// index 1 is y
			result[2] = 0;// index 2 is d ... ax+by = d
			//System.out.println(result[0]+" "+result[1]+" "+result[2]);
			return result;
		}
		
		int []result_temp = extendedEuclidsAlgo(b, a%b);
		int []final_result = {result_temp[0],result_temp[2],result_temp[1]-(a/b)*result_temp[2]};
		//System.out.println(final_result[0]+" "+final_result[1]+" "+final_result[2]);
		return final_result;
	}
	
	/**
	 * This method implements the modular exponentiation algorithm as defined in the CLRS text book.
	 * It finds out the result of (a^b) mod n, even when b is very very large
	 * @param a An integer that has to be raised to the power b
	 * @param b An integer that denotes the power to which a has to be raised.
	 * @param n An integer based on which all multiplication operations are performed (mod n)
	 * @return An integer containing the result of ((a ^ b) mod n)
	 */
	public int modularExponentiator(int a, int b, int n)
	{
		int c = 0;
		int d = 1;
		String binaryB = Integer.toBinaryString(b);
		
		for(int i = 0; i < binaryB.length(); i++)
		{
			c = 2 * c;
			d = (d * d) % n;
			if(binaryB.charAt(i) == '1')
			{
				c++;
				d = (d * a) % n;
			}
		}
		
		return d;
	}
		
	/**
	 * Encrypts a message using the Schmidt-Samoa Algorithm. The message is split into blocks of size
	 * BLOCK_SIZE and each block is encrypted to form a cipher string. If a given block is less than the 
	 * BLOCK_SIZE, then the toNLengthString() method is called to 
	 * convert the block to a string of size BLOCK_SIZE.
	 * @param message A string of plaintext.
	 * @return A string containing the cipher text
	 */
	public String encrypt(String message)
	{
		int []cipher = new int[message.length()];
		String cipherString = "";
		for(int i = 0; i < message.length(); i++)
		{
			cipher[i] = encrypt(message.charAt(i));
			cipherString += toNLengthString("" + cipher[i], BLOCK_SIZE);
		}	
	
		System.out.println("STRING = " + cipherString);
		return cipherString;
	}
	
	/**
	 * This method encrypts only an integer. 
	 * It is used by the encrypt(String) method on each block of the plaintext	 * 
	 * @param m An integer that has to be encrypted
	 * @return An integer containing an encrypted version of m, i.e., ((m ^ public_key) mod (public_key))
	 */
	public int encrypt(int m)
	{		
		return modularExponentiator(m, public_key, public_key);
	}
	
	/**
	 * This method decrypts only  an integer. It is used by the decrypt(String) 
	 * method on each block of the ciphertext.	
	 * @param c An integer that has to be decrypted. It should satisfy the constraint ---- 0 < M < (p * q)
	 * @return An integer containing the decrypted version of c, i.e., ((c ^ private_key) mod(p * q))
	 */
	public int decrypt(int c)
	{
		return modularExponentiator(c, private_key, p * q);
	}
	
	/**
	 * Decrypts a message using the Schmidt-Samoa Algorithm.
	 * The message is split into blocks of size
	 * BLOCK_SIZE and each block is decrypted to form a plaintext string. 
	 * @param message A string of cipher text.
	 * @return A string containing the plain text
	 */
	public String decrypt(String cipher)
	{
		String plaintext = "";
		int [] message = new int[cipher.length()];
		for(int i = 0; i < cipher.length() / BLOCK_SIZE; i++)
		{
			message[i] = Integer.parseInt(cipher.substring(i * BLOCK_SIZE,
						 i * BLOCK_SIZE + BLOCK_SIZE));
			message[i] = decrypt(message[i]);
			plaintext += (char)message[i];
		}
		return plaintext;
	}	
	
	/**
	 * Displays all details of the following values:
	 * 		p
	 * 		q 
	 * 		Public Key
	 * 		Private Key
	 * @return A string containing these values
	 */
	public String display()
	{
		String message = "Algorithm details \n p = "+p + " q = "+ 
				q + "\nPublic Key is "+public_key+
				"\nPrivate Key is "+private_key+"\n";
		System.out.println(message);
		return message;
	}

}
