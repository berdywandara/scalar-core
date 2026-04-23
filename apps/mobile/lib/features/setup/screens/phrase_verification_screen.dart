import 'package:flutter/material.dart';
import 'backup_options_screen.dart';

class PhraseVerificationScreen extends StatefulWidget {
  final List<String> originalWords;
  const PhraseVerificationScreen({super.key, required this.originalWords});

  @override
  State<PhraseVerificationScreen> createState() => _PhraseVerificationScreenState();
}

class _PhraseVerificationScreenState extends State<PhraseVerificationScreen> {
  final TextEditingController _controller = TextEditingController();
  bool _isError = false;

  void _verify() {
    if (_controller.text.trim().toLowerCase() == widget.originalWords[0]) {
      Navigator.push(context, MaterialPageRoute(builder: (_) => const BackupOptionsScreen()));
    } else {
      setState(() => _isError = true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('VERIFICATION')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Verify Word #1', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            const SizedBox(height: 16),
            const Text('Sesuai protokol Scalar, masukkan kata pembuka domain Anda:', style: TextStyle(color: Color(0xFF8A8A93))),
            const SizedBox(height: 24),
            TextField(
              controller: _controller,
              decoration: InputDecoration(
                hintText: 'Type word #1 here...',
                errorText: _isError ? 'Word mismatch. Remember the first word is "scalar".' : null,
                filled: true,
                fillColor: const Color(0xFF1A1A24),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
              ),
            ),
            const Spacer(),
            ElevatedButton(onPressed: _verify, style: ElevatedButton.styleFrom(minimumSize: const Size.fromHeight(56)), child: const Text('VERIFY & FINISH')),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}
