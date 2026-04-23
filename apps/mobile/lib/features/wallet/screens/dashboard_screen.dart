import 'package:flutter/material.dart';
import 'receive_screen.dart';
import 'send_screen.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SCALAR WALLET', style: TextStyle(letterSpacing: 4)), centerTitle: true, elevation: 0),
      body: Column(
        children: [
          _buildBalanceCard(),
          const SizedBox(height: 32),
          _buildActionButtons(context),
          const Spacer(),
          _buildSecurityStatus(),
          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _buildBalanceCard() {
    return Container(
      margin: const EdgeInsets.all(24),
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(color: const Color(0xFF1A1A24), borderRadius: BorderRadius.circular(24), border: Border.all(color: const Color(0xFF00FF9D).withOpacity(0.2))),
      child: const Column(children: [
        Text('AVAILABLE BALANCE', style: TextStyle(color: Color(0xFF8A8A93), letterSpacing: 1)),
        SizedBox(height: 16),
        Text('1,250.00 SCL', style: TextStyle(fontSize: 36, fontWeight: FontWeight.bold, color: Colors.white)),
        SizedBox(height: 8),
        Text('≈ $ 12,500.00', style: TextStyle(color: Color(0xFF00FF9D))),
      ]),
    );
  }

  Widget _buildActionButtons(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 24),
      child: Row(children: [
        Expanded(child: _button(Icons.south_west, 'RECEIVE', () => Navigator.push(context, MaterialPageRoute(builder: (_) => const ReceiveScreen())))),
        const SizedBox(width: 16),
        Expanded(child: _button(Icons.north_east, 'SEND', () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SendScreen())))),
      ]),
    );
  }

  Widget _button(IconData icon, String label, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 24),
        decoration: BoxDecoration(color: const Color(0xFF1A1A24), borderRadius: BorderRadius.circular(16)),
        child: Column(children: [Icon(icon, color: const Color(0xFF00FF9D)), const SizedBox(height: 8), Text(label, style: const TextStyle(fontWeight: FontWeight.bold))]),
      ),
    );
  }

  Widget _buildSecurityStatus() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      decoration: BoxDecoration(color: const Color(0xFF1A1A24), borderRadius: BorderRadius.circular(30)),
      child: const Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(Icons.verified_user, size: 14, color: Color(0xFF00FF9D)),
        SizedBox(width: 8),
        Text('STATUS: SECURE | POST-QUANTUM ACTIVE', style: TextStyle(fontSize: 10, color: Color(0xFF00FF9D), fontWeight: FontWeight.bold)),
      ]),
    );
  }
}
