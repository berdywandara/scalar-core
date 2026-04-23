import 'package:flutter/material.dart';
import 'package:scalar_wallet/features/setup/screens/mnemonic_display_screen.dart';

class PhraseGenerationScreen extends StatefulWidget {
  const PhraseGenerationScreen({super.key});

  @override
  State<PhraseGenerationScreen> createState() => _PhraseGenerationScreenState();
}

class _PhraseGenerationScreenState extends State<PhraseGenerationScreen> {
  @override
  void initState() {
    super.initState();
    _startGeneration();
  }

  void _startGeneration() async {
    await Future.delayed(const Duration(seconds: 3));
    if (!mounted) return;
    // Simulasi mnemonic dari Rust
    List<String> dummyMnemonic = List.generate(24, (i) => i == 0 ? "scalar" : "word$i");
    Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => MnemonicDisplayScreen(words: dummyMnemonic)));
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CircularProgressIndicator(color: Color(0xFF00FF9D)),
            SizedBox(height: 24),
            Text('GENERATING MASTER SEED', style: TextStyle(letterSpacing: 2)),
            SizedBox(height: 8),
            Text('Gathering entropy from your device...', style: TextStyle(color: Color(0xFF8A8A93))),
          ],
        ),
      ),
    );
  }
}
