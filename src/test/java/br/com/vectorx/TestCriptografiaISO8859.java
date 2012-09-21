package br.com.vectorx;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
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
	private String salt2 = "TesteThisBefore";
	private int cesarCipher;
	private BlowfishCryptox x;
	private BlowfishCryptox x2;

	@Before
	public void setUp() {
		Random random = new Random(System.currentTimeMillis());
		cesarCipher = random.nextInt(64);
		x = BlowfishCryptox.getInstance(salt, cesarCipher,
				Charset.forName("ISO-8859-1"));
		x2 = BlowfishCryptox.getInstance(salt2, cesarCipher,
				Charset.forName("ISO-8859-1"));
		assertNotNull(x);
		assertNotNull(x2);
		senhaCriptografada = x.crypt(senha);
	}

	@Test
	public void criptografia() {
		assertNotNull(senhaCriptografada);
		assertFalse(senha.equals(senhaCriptografada));
	}

	@Test
	public void descriptografa() {
		String senhaDescriptografada = x.decrypt(senhaCriptografada);
		assertNotNull(senhaDescriptografada);
		assertEquals(senha, senhaDescriptografada);
	}

	@Test
	public void metodoChecaSenha() {
		assertTrue(x.checaSenha(senha, senhaCriptografada));
	}

	@Test
	public void metodoOutraInstancia() {
		String senhaCriptografada2 = x2.crypt(senha);
		assertNotSame(senhaCriptografada, senhaCriptografada2);
		assertFalse(x.checaSenha(senha, senhaCriptografada2));
		assertTrue(x2.checaSenha(senha, senhaCriptografada2));
		assertEquals(senha, x2.decrypt(senhaCriptografada2));
	}
}
