// Gerekli modüller
const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const pool = require("../db");  // db.js dosyanın yolu doğru mu? Eğer src içindeyse: ./db

// GİRİŞ ENDPOINTİ: /api/auth/login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // 1. E-posta ve şifre boşsa hata
  if (!email || !password) {
    return res.status(400).json({ message: "E-posta ve şifre zorunlu." });
  }

  try {
    // 2. Kullanıcıyı veritabanından bul
    const [rows] = await pool.execute(
      "SELECT * FROM users WHERE email = ? LIMIT 1",
      [email]
    );

    const user = rows[0];
    if (!user) {
      return res.status(401).json({ message: "Kullanıcı bulunamadı." });
    }

    // 3. Şifreyi karşılaştır
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Şifre hatalı." });
    }

    // 4. JWT token oluştur
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET, // .env dosyanda mutlaka JWT_SECRET olmalı!
      { expiresIn: "2d" }
    );

    // 5. Başarılı yanıt
    res.json({
      token,
      role: user.role,
      email: user.email,
      id: user.id,
      message: "Giriş başarılı."
    });

  } catch (err) {
    // Hata logla ve kullanıcıya dön
    console.error("Login error:", err);
    res.status(500).json({ message: "Sunucu hatası." });
  }
});

module.exports = router;
