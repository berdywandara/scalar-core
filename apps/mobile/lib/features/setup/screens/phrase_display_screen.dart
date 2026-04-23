import 'package:flutter/material.dart';
import 'phrase_verification_screen.dart';

class PhraseDisplayScreen extends StatelessWidget {
  final List<String> words;
  const PhraseDisplayScreen({super.key, required this.words});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('RECOVERY PHRASE')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('Catat 24 kata ini.', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            const Text('Urutan sangat penting. Kata pertama ("scalar") adalah pengunci domain jaringan.', style: TextStyle(color: Color(0xFF8A8A93))),
            const SizedBox(height: 32),
            Expanded(
              child: GridView.builder(
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(crossAxisCount: 3, childAspectRatio: 2.2, crossAxisSpacing: 8, mainAxisSpacing: 8),
                itemCount: words.length,
                itemBuilder: (context, index) => Container(
                  decoration: BoxDecoration(color: const Color(0xFF1A1A24), borderRadius: BorderRadius.circular(8)),
                  child: Center(child: Text('${index + 1}. ${words[index]}', style: const TextStyle(fontSize: 12))),
                ),
              ),
            ),
            ElevatedButton(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => PhraseVerificationScreen(originalWords: words))), child: const Text('I HAVE WRITTEN IT DOWN')),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}
