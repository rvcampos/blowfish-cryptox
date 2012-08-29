package br.com.vectorx;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.nio.charset.Charset;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

public class TestCriptografiaISO8859 {

	private String senha = "MEUTESTE123";
	private String senhaCriptografada = null;
	private String salt = "TesteThisAfter";
	private int cesarCipher;
	private BlowfishCryptox x;

	@Before
	public void setUp() {
		Random random = new Random(System.currentTimeMillis());
		cesarCipher = random.nextInt(64);
		x = BlowfishCryptox.getInstance(salt, cesarCipher, Charset.forName("ISO8859-1"));
		assertNotNull(x);
	}

	@Test
	public void criptografia() {
		senhaCriptografada = x.crypt(senha);
		assertNotNull(senhaCriptografada);
		assertFalse(senha.equals(senhaCriptografada));
		descriptografa();
		metodoChecaSenha();
	}

	public void descriptografa() {
		String senhaDescriptografada = x.decrypt(senhaCriptografada);
		assertNotNull(senhaDescriptografada);
		assertEquals(senha, senhaDescriptografada);
	}

	public void metodoChecaSenha() {
		assertTrue(x.checaSenha(senha, senhaCriptografada));
	}
}
