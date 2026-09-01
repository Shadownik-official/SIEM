"use client";

import Link from 'next/link';

const Navbar = () => {
  return (
    <nav className="bg-blue-600 text-white p-4">
      <div className="container mx-auto flex justify-between items-center">
        <Link href="/" className="text-xl font-bold">
          SIEM Dashboard
        </Link>
        <div className="space-x-4">
          <Link href="/dashboard" className="hover:text-blue-200">
            Dashboard
          </Link>
          <Link href="/events" className="hover:text-blue-200">
            Events
          </Link>
          <Link href="/threats" className="hover:text-blue-200">
            Threats
          </Link>
          <Link href="/settings" className="hover:text-blue-200">
            Settings
          </Link>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
