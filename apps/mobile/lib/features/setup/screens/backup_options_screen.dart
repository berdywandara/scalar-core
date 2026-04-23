import 'package:flutter/material.dart';
import '../../wallet/screens/dashboard_screen.dart';

class BackupOptionsScreen extends StatelessWidget {
  const BackupOptionsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Icon(Icons.cloud_off_outlined, size: 64, color: Color(0xFF00FF9D)),
            const SizedBox(height: 32),
            const Text(
              'BACKUP OPTIONS',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 48),
            _backupCard(context, Icons.edit_note, 'Paper Backup (Recommended)', 'Simpan secara fisik di tempat aman.'),
            const SizedBox(height: 16),
            _backupCard(context, Icons.vibration, 'Hardware Encrypted', 'Gunakan Scalar Hardware Standard.'),
            const Spacer(),
            TextButton(
              onPressed: () => Navigator.pushAndRemoveUntil(context, MaterialPageRoute(builder: (_) => const DashboardScreen()), (route) => false),
              child: const Text('FINISH SETUP', style: TextStyle(color: Color(0xFF00FF9D))),
            ),
          ],
        ),
      ),
    );
  }

  Widget _backupCard(BuildContext context, IconData icon, String title, String desc) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: const Color(0xFF1A1A24), borderRadius: BorderRadius.circular(12)),
      child: ListTile(
        leading: Icon(icon, color: const Color(0xFF00FF9D)),
        title: Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
        subtitle: Text(desc, style: const TextStyle(fontSize: 12)),
      ),
    );
  }
}
