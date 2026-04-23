import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

class ReceiveScreen extends StatelessWidget {
  const ReceiveScreen({super.key});

  final String dummyAddress = "scl1q_postquantum_x7f9a...v3k2m_nullifier_ready";

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('RECEIVE SCL', style: TextStyle(letterSpacing: 2)),
        backgroundColor: Colors.transparent,
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: QrImageView(
                  data: dummyAddress,
                  version: QrVersions.auto,
                  size: 200.0,
                  eyeStyle: const QrEyeStyle(
                    eyeShape: QrEyeShape.square,
                    color: Colors.black,
                  ),
                ),
              ),
              const SizedBox(height: 32),
              const Text('YOUR PUBLIC ADDRESS', style: TextStyle(color: Color(0xFF8A8A93))),
              const SizedBox(height: 8),
              Text(
                dummyAddress.substring(0, 20) + '...' + dummyAddress.substring(dummyAddress.length - 10),
                style: const TextStyle(fontSize: 16, color: Color(0xFF00FF9D)),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              OutlinedButton.icon(
                onPressed: () {},
                icon: const Icon(Icons.copy),
                label: const Text('COPY ADDRESS'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: const Color(0xFF00FF9D),
                  side: const BorderSide(color: Color(0xFF00FF9D)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
