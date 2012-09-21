package br.com.vectorx;

/*
 * =============================================================================
 * Copyright (c) 2012 Renan Vizza Campos/Vector X. All rights reserved. Just Kidding.
 * LICENSE: Apache 2.0
 * Use como quiser, se for melhorar me avise!!
 * Feel free to use this class/project, if you enhance it, please, contact me!
 * 
 * contact: renanvcampos@gmail.com
 */
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classe que criptografa e descriptografa somente para <b><br>
 * Blowfish<br>
 * How to use: BlowfishCryptox myCrypt = BlowfishCryptox.
 * {@link #getInstance(String, int)}
 * 
 * @author renan.campos
 * 
 */
public class BlowfishCryptox {

	private int cifraCesar = 16;
	private Charset charset;
	private Cipher encrypt;
	private Cipher decrypt;

	/**
	 * Enumerador contendo dois casos: <br>
	 * {@link #ENCRYPT}<br>
	 * {@link #DECRYPT}
	 * 
	 * @author renan.campos
	 * 
	 */
	private static enum Mode {
		/**
		 * Criptografar
		 */
		ENCRYPT,
		/**
		 * Descriptografar
		 */
		DECRYPT;
	}

	private static Logger log = LoggerFactory.getLogger(BlowfishCryptox.class);

	/**
	 * Construtor private
	 * 
	 * @param palavraChave
	 *            Palavra chave
	 * @param algoritmo
	 *            Algoritmo a ser utilizado
	 * @param cifraCesar
	 *            em quantos numeros os caracteres serão trocados
	 * @param charset
	 * @throws IllegalArgumentException
	 */
	private BlowfishCryptox(String palavraChave, String algoritmo,
			int cifraCesar, Charset charset) throws IllegalArgumentException {
		try {
			validateInput(palavraChave, cifraCesar, charset);
			this.charset = charset;
			SecretKey chave = new SecretKeySpec(palavraChave.getBytes(charset),
					algoritmo);
			this.encrypt = Cipher.getInstance(algoritmo);
			this.decrypt = Cipher.getInstance(algoritmo);
			this.encrypt.init(Cipher.ENCRYPT_MODE, chave);
			this.decrypt.init(Cipher.DECRYPT_MODE, chave);
			this.cifraCesar = cifraCesar;
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Valida o input<br>
	 * As validações feitas são: <li>Palavra Chave nula</li> <li>Palavra Chave
	 * com tamanho maior que 16</li>
	 * 
	 * @param palavraChave
	 *            - palavra chave (Salt)
	 * @param cifraCesar
	 *            - cifra de cesar (caesar cipher, shift chars)
	 * @param charset
	 *            - Charset utilizado e.g (UTF-8, ISO-8859-1)
	 * @throws IllegalArgumentException
	 */
	private void validateInput(String palavraChave, int cifraCesar,
			Charset charset) throws IllegalArgumentException {
		// Checagem de Nulo
		if (palavraChave == null) {
			throw new IllegalArgumentException(
					"Palavra chave (sal) não pode ser nula");
		}
		// Checagem de tamanho
		if (palavraChave != null && palavraChave.length() > 16) {
			throw new IllegalArgumentException(
					"Tamanho da Palavra chave (sal) maior que 16");
		}
	}

	/**
	 * Método getInstance com charset padrão UTF-8
	 * 
	 * @param palavraChave
	 *            chave para criar salt (sal)
	 * @param algoritmo
	 *            algoritmo para criptografia
	 * @param val
	 *            valor para cifra de cesar
	 * @return instancia de {@link BlowfishCryptox}
	 */
	public static BlowfishCryptox getInstance(String palavraChave, int val) {
		return new BlowfishCryptox(palavraChave, "Blowfish", val,
				Charset.forName("UTF-8"));
	}

	/**
	 * Checa se uma senha digitada é igual a uma senha Encriptada
	 * 
	 * @param senha
	 *            senha normal
	 * @param senhaEncriptada
	 * @return senha corresponde à senha encriptada?
	 */
	public boolean checaSenha(String senha, String senhaEncriptada) {
		boolean result = false;
		String cryptPass = crypt(senha);
		if (cryptPass != null && cryptPass.equals(senhaEncriptada)) {
			result = true;
		}

		return result;
	}

	/**
	 * Método getInstance com charset definido pelo usuário
	 * 
	 * @param palavraChave
	 *            chave para criar salt (sal)
	 * @param algoritmo
	 *            algoritmo para criptografia
	 * @param val
	 *            valor para cifra de cesar
	 * @param cs
	 *            Charset
	 * @return
	 */
	public static BlowfishCryptox getInstance(String palavraChave, int val,
			Charset cs) {
		return new BlowfishCryptox(palavraChave, "Blowfish", val, cs);
	}

	/**
	 * Criptografa uma String
	 * 
	 * @param str
	 *            - String a ser criptografada
	 * @return String criptografada
	 * @throws UnsupportedEncodingException
	 *             - Problema de charset
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String crypt(String str) {
		byte[] enc = null;
		byte[] cc = null;
		// Retorna a string com aplicação cifra de cesar
		str = this.cifraCesar(str, Mode.ENCRYPT);
		try {
			// Pega o byte[] correspondente à String para o charset informado
			cc = str.getBytes(this.charset);
			// Cipher
			enc = this.encrypt.doFinal(cc);
		} catch (Exception e) {
			log.error("Crypt", e);
		}
		// Faz encoding com Base64
		return new String(Base64.encodeBase64(enc));
	}

	/**
	 * Aplica o <a href=http://pt.wikipedia.org/wiki/Cifra_de_César>conceito
	 * Cifra de cesar</a> para a String, dependendo de seu modo
	 * 
	 * @param str
	 *            - String a ser aplicada
	 * @param modo
	 *            {@link Mode}
	 * @return String alterada
	 */
	private String cifraCesar(String str, Mode modo) {
		char[] newStr = new char[str.length()];
		int i = 0;
		// Caso para criptografia
		if (modo.equals(Mode.ENCRYPT)) {
			for (char c : str.toCharArray()) {
				// Valor do char + int da cifra de cesar
				newStr[i] = (char) (c + this.cifraCesar);
				i++;
			}
		} // Caso para descriptografia
		else {
			for (char c : str.toCharArray()) {
				// Valor do char - int da cifra de cesar
				newStr[i] = (char) (c - this.cifraCesar);
				i++;
			}
		}
		// Retorna uma String com o valor do char[]
		return String.copyValueOf(newStr);
	}

	/**
	 * Descriptografia uma string criptografada
	 * 
	 * @param str
	 *            String criptografada
	 * @return String descriptografada
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String decrypt(String str) {
		byte[] dec;
		byte[] cc = null;
		try {
			// Decoding com base64
			dec = Base64.decodeBase64(str.getBytes(this.charset));
			// Cipher
			cc = this.decrypt.doFinal(dec);
		} catch (Exception e) {
			log.error("Decrypt", e);
			return null;
		}
		// Retorna uma String aplicando a cifra de cesar para descriptografia
		return this.cifraCesar(new String(cc, this.charset), Mode.DECRYPT);
	}
}
