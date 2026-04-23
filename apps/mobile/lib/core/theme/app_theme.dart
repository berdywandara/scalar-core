import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: const Color(0xFF0D0D12),
      primaryColor: const Color(0xFF00FF9D), // Matrix/Cypherpunk Green
      colorScheme: const ColorScheme.dark(
        primary: Color(0xFF00FF9D),
        secondary: Color(0xFF8A8A93),
        surface: Color(0xFF1A1A24),
      ),
      textTheme: GoogleFonts.ibmPlexMonoTextTheme(
        ThemeData.dark().textTheme.copyWith(
          displayLarge: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
          bodyLarge: const TextStyle(color: Color(0xFFD0D0D5)),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF00FF9D),
          foregroundColor: const Color(0xFF0D0D12),
          padding: const EdgeInsets.symmetric(vertical: 16),
          textStyle: const TextStyle(fontWeight: FontWeight.bold, letterSpacing: 1.2),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
    );
  }
}
