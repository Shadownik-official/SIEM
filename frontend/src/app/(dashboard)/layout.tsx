import DashboardLayout from '@/components/layout/DashboardLayout'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'SIEM Dashboard',
  description: 'Next-Generation Security Information and Event Management'
}

export default function Layout({
  children,
}: {
  children: React.ReactNode
}) {
  return <DashboardLayout>{children}</DashboardLayout>
} 