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
 * How to use: BlowfishCryptox myCrypt = BlowfishCryptox.{@link #getInstance(String, int)}
 * 
 * @author renan.campos
 * 
 */
public class BlowfishCryptox {

    private int     cifraCesar = 16;
    private Charset charset;
    private Cipher  encrypt;
    private Cipher  decrypt;

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
     * valida o input
     * 
     * @param palavraChave
     * @param cifraCesar
     * @param charset
     * @return
     * @throws IllegalArgumentException
     */
    private void validateInput(String palavraChave, int cifraCesar,
            Charset charset) throws IllegalArgumentException {
        if (palavraChave == null) {
            throw new IllegalArgumentException(
                    "Palavra chave (sal) não pode ser nula");
        }
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
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String crypt(String str) {
        byte[] enc = null;
        byte[] cc = null;
        str = this.cifraCesar(str, Mode.ENCRYPT);
        try {
            cc = str.getBytes(this.charset);
            enc = this.encrypt.doFinal(cc);
        } catch (Exception e) {
            log.error("Crypt", e);
        }
        return new String(Base64.encodeBase64(enc));
    }

    /**
     * Aplica o <a href=http://pt.wikipedia.org/wiki/Cifra_de_César>conceito Cifra de cesar</a> para
     * a String, dependendo de seu modo
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
        if (modo.equals(Mode.ENCRYPT)) {
            for (char c : str.toCharArray()) {
                newStr[i] = (char) (c + this.cifraCesar);
                i++;
            }
        } else {
            for (char c : str.toCharArray()) {
                newStr[i] = (char) (c - this.cifraCesar);
                i++;
            }
        }

        return String.copyValueOf(newStr);
    }

    /**
     * Decriptografa uma string criptografada
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
            dec = Base64.decodeBase64(str.getBytes(this.charset));
            cc = this.decrypt.doFinal(dec);
        } catch (Exception e) {
            log.error("Decrypt", e);
            return null;
        }
        return this.cifraCesar(new String(cc, this.charset), Mode.DECRYPT);
    }

    // public static void main(String[] args) throws UnsupportedEncodingException,
    // IllegalBlockSizeException, BadPaddingException {
    // String sal = "rbacpass ";
    // String pass = "admin";
    // BlowfishCryptox j = BlowfishCryptox.getInstance(sal, 3000);
    // String x = j.crypt(pass);
    // System.out.println(x);
    // System.out.println(j.decrypt(x));
    // System.out.println(j.checaSenha(pass, x));
    // }
}
