import 'package:flutter/material.dart';
import 'phrase_generation_screen.dart';

class SecurityFoundationScreen extends StatelessWidget {
  const SecurityFoundationScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          children: [
            const Spacer(),
            const Icon(Icons.shield_outlined, size: 64, color: Color(0xFF00FF9D)),
            const SizedBox(height: 24),
            Text('SECURITY FOUNDATION', style: Theme.of(context).textTheme.headlineSmall?.copyWith(letterSpacing: 2, fontWeight: FontWeight.bold)),
            const SizedBox(height: 48),
            _buildFeature(Icons.lock_reset, 'Post-Quantum Defense', 'Kriptografi SPHINCS+ untuk melawan ancaman komputer kuantum.'),
            _buildFeature(Icons.visibility_off, 'Zero-Knowledge Privacy', 'Identitas dan saldo tersembunyi di balik zk-STARK proofs.'),
            _buildFeature(Icons.account_tree_outlined, 'Immutable Truth', 'Setiap state diverifikasi oleh Sparse Merkle Tree secara independen.'),
            const Spacer(),
            ElevatedButton(
              onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const PhraseGenerationScreen())),
              style: ElevatedButton.styleFrom(minimumSize: const Size.fromHeight(56)),
              child: const Text('I UNDERSTAND & PROCEED'),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildFeature(IconData icon, String title, String desc) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Row(
        children: [
          Icon(icon, color: const Color(0xFF00FF9D)),
          const SizedBox(width: 16),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
            Text(desc, style: const TextStyle(color: Color(0xFF8A8A93), fontSize: 12)),
          ])),
        ],
      ),
    );
  }
}
