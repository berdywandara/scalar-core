import 'phrase_verification_screen.dart';
import 'package:flutter/material.dart';

class MnemonicDisplayScreen extends StatelessWidget {
  final List<String> words;
  const MnemonicDisplayScreen({super.key, required this.words});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('BACKUP WALLET')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Tulis 24 kata rahasia ini di kertas.',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            const Text(
              'Ini adalah satu-satunya cara untuk memulihkan aset Anda jika perangkat hilang.',
              style: TextStyle(color: Color(0xFF8A8A93)),
            ),
            const SizedBox(height: 32),
            Expanded(
              child: GridView.builder(
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 3,
                  childAspectRatio: 2.5,
                  crossAxisSpacing: 8,
                  mainAxisSpacing: 8,
                ),
                itemCount: words.length,
                itemBuilder: (context, index) => Container(
                  decoration: BoxDecoration(
                    color: const Color(0xFF1A1A24),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Center(
                    child: Text('${index + 1}. ${words[index]}'),
                  ),
                ),
              ),
            ),
            ElevatedButton(
              onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const PhraseVerificationScreen())),
                // Navigasi ke Dashboard
              },
              child: const Text('SAYA SUDAH MENCATATNYA'),
            ),
          ],
        ),
      ),
    );
  }
}
