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
 * Classe que criptografa e descriptografa somente para <b> Blowfish</b><br>
 * How to use: BlowfishCryptox myCrypt = BlowfishCryptox
 * {@link BlowfishCryptox#getInstance(String, int)}<br>
 * <br>
 * Getting too much <b>java.security.InvalidKeyException: Illegal key size or
 * default parameters?</b> <br>
 * Check Oracle Unlimited JCE <br>
 * If your country laws do not allow you to use that, use cifraCesar between -64
 * AND 64 and salt length <=16
 * 
 * @see <a
 *      href="http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html">Oracle
 *      Unlimited JCE</a>
 * @author renan.campos
 * 
 */
public class BlowfishCryptox {

	/**
	 * Tamanho máximo da palavra salt caso não tenha <a href=
	 * "http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html"
	 * >Oracle Unlimited JCE</a>
	 */
	private static final int LIMITEDSALTLENGTH = 16;
	/**
	 * Tamanho máximo da palavra salt caso tenha <a href=
	 * "http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html"
	 * >Oracle Unlimited JCE</a>
	 */
	private static final int UNLIMITEDJCESALT = 56;
	/**
	 * Valor máximo Cifra de César
	 */
	private static final int CIFRAMAX = 128;
	/**
	 * Valor mínimo Cifra de César
	 */
	private static final int CIFRAMIN = -128;
	/**
	 * Valor cifra de cesar
	 */
	private int cifraCesar = CIFRAMAX;
	private Charset charset;
	/**
	 * {@link Cipher} para passo de criptografia
	 */
	private Cipher encrypt;
	/**
	 * {@link Cipher} para passo de descriptografia
	 */
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

	private static Logger LOG = LoggerFactory.getLogger(BlowfishCryptox.class);

	/**
	 * Construtor private. Define o tamanho máximo da palavra salt de acordo com
	 * o SecurityPolice instalado
	 * 
	 * @param palavraChave
	 *            Palavra chave
	 * @param algoritmo
	 *            Algoritmo a ser utilizado (no caso o Blowfish)
	 * @param cifraCesar
	 *            em quantos numeros os caracteres serão trocados
	 * @param charset
	 * @throws IllegalArgumentException
	 */
	private BlowfishCryptox(String palavraChave, String algoritmo,
			int cifraCesar, Charset charset) throws IllegalArgumentException {
		try {
			int maxSalt = LIMITEDSALTLENGTH;
			// Checagem para ver se tem JCE Unlimited Strength Policy instalado
			if (Cipher.getMaxAllowedKeyLength(algoritmo) > BlowfishCryptox.CIFRAMAX) {
				maxSalt = BlowfishCryptox.UNLIMITEDJCESALT;
			}
			validateInput(palavraChave, cifraCesar, maxSalt);
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
	 * As validações feitas são:
	 * <ul>
	 * <li>Palavra Chave nula</li>
	 * <li>Palavra Chave com tamanho maior que 16</li>
	 * <li>cifra de cesar < -128 ou > 128</li>
	 * </ul>
	 * 
	 * @param palavraChave
	 *            - palavra chave (Salt)
	 * @param cifraCesar
	 *            - cifra de cesar (caesar cipher, shift chars) - Min -128 and
	 *            Max 128
	 * @param maxSaltLength
	 *            - Tamanho máximo da palavra chave (salt)
	 * @throws IllegalArgumentException
	 */
	private void validateInput(String palavraChave, int cifraCesar,
			int maxSaltLength) throws IllegalArgumentException {
		// Checagem de Nulo
		if (palavraChave == null || palavraChave.trim().isEmpty()) {
			throw new IllegalArgumentException(
					"Palavra chave (sal) não pode ser nula");
		}
		// Checagem de tamanho da palavra Salt
		if (palavraChave.length() > maxSaltLength) {
			throw new IllegalArgumentException(
					"Tamanho da Palavra chave (sal) maior que " + maxSaltLength);
		}

		// Checagem do tamanho da cifra de cesar
		if (cifraCesar < BlowfishCryptox.CIFRAMIN
				|| cifraCesar > BlowfishCryptox.CIFRAMAX) {
			throw new IllegalArgumentException(
					"Cifra de Cesar deve estar entre -128 e 128");
		}
	}

	/**
	 * Método getInstance com charset padrão UTF-8
	 * 
	 * @param palavraChave
	 *            chave para criar salt (sal)
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
	 *            chave para criar salt (sal) com tamanho máximo 16 ou 56 (se
	 *            tiver <a href=
	 *            "http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html"
	 *            >Oracle Unlimited JCE</a> instalado)
	 * @param val
	 *            valor para cifra de cesar (> -128 e < 128)
	 * @param cs
	 *            Charset
	 * @return instancia de {@link BlowfishCryptox}
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
		String crypted = this.cifraCesar(str, Mode.ENCRYPT);
		try {
			// Pega o byte[] correspondente à String para o charset informado
			cc = crypted.getBytes(this.charset);
			// Cipher
			enc = this.encrypt.doFinal(cc);
		} catch (IllegalBlockSizeException e) {
			LOG.error("Falha de conversão. Tamanho de Block Size", e);
			return null;
		} catch (BadPaddingException e) {
			LOG.error("Falha de BadPaddingException. Tamanho de Block Size", e);
			return null;
		}
		// Faz encoding com Base64
		return new String(Base64.encodeBase64(enc));
	}

	/**
	 * Aplica o conceito <a href=http://pt.wikipedia.org/wiki/Cifra_de_César>
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
	 * Descriptografa uma string criptografada
	 * 
	 * @param str
	 *            String criptografada
	 * @return String descriptografada
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
		} catch (IllegalBlockSizeException e) {
			LOG.error("Falha de conversão. Tamanho de Block Size", e);
			return null;
		} catch (BadPaddingException e) {
			LOG.error("Falha de BadPaddingException. Tamanho de Block Size", e);
			return null;
		}
		// Retorna uma String aplicando a cifra de cesar para descriptografia
		return this.cifraCesar(new String(cc, this.charset), Mode.DECRYPT);
	}
}
