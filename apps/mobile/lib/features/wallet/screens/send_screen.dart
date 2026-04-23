import 'package:flutter/material.dart';

class SendScreen extends StatefulWidget {
  const SendScreen({super.key});

  @override
  State<SendScreen> createState() => _SendScreenState();
}

class _SendScreenState extends State<SendScreen> {
  bool _isProcessing = false;
  String _processText = "";

  void _simulateTransaction() async {
    setState(() {
      _isProcessing = true;
      _processText = "1/3: Generating Zero-Knowledge Proof...";
    });
    
    await Future.delayed(const Duration(seconds: 2));
    if (!mounted) return;
    setState(() => _processText = "2/3: Applying SPHINCS+ Post-Quantum Signature...");

    await Future.delayed(const Duration(seconds: 2));
    if (!mounted) return;
    setState(() => _processText = "3/3: Broadcasting to Scalar Network...");

    await Future.delayed(const Duration(seconds: 1));
    if (!mounted) return;
    
    // Kembali ke dashboard setelah sukses
    Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('SEND SCL', style: TextStyle(letterSpacing: 2)),
        backgroundColor: Colors.transparent,
      ),
      body: _isProcessing 
        ? Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const CircularProgressIndicator(color: Color(0xFF00FF9D)),
                const SizedBox(height: 24),
                Text(
                  _processText,
                  style: const TextStyle(color: Color(0xFF00FF9D), fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),
                const Text(
                  'Ensuring Maximum Privacy & Security',
                  style: TextStyle(color: Color(0xFF8A8A93), fontSize: 12),
                )
              ],
            ),
          )
        : Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TextField(
                  decoration: InputDecoration(
                    labelText: 'Recipient Address',
                    labelStyle: const TextStyle(color: Color(0xFF8A8A93)),
                    enabledBorder: const OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF8A8A93))),
                    focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00FF9D))),
                    suffixIcon: IconButton(icon: const Icon(Icons.qr_code_scanner, color: Color(0xFF00FF9D)), onPressed: () {}),
                  ),
                ),
                const SizedBox(height: 24),
                const TextField(
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(
                    labelText: 'Amount (SCL)',
                    labelStyle: TextStyle(color: Color(0xFF8A8A93)),
                    enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF8A8A93))),
                    focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00FF9D))),
                  ),
                ),
                const Spacer(),
                ElevatedButton(
                  onPressed: _simulateTransaction,
                  child: const Text('CONFIRM & SEND'),
                ),
              ],
            ),
          ),
    );
  }
}
