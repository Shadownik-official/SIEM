"use client";

import { ArrowUpIcon } from '@heroicons/react/24/outline';

interface EventSummaryCardProps {
  totalEvents: number;
}

export const EventSummaryCard: React.FC<EventSummaryCardProps> = ({ totalEvents }) => {
  return (
    <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-blue-500 hover:shadow-lg transition-shadow">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-semibold text-gray-700">Total Events</h2>
          <p className="text-3xl font-bold text-blue-600">{totalEvents}</p>
        </div>
        <ArrowUpIcon className="h-8 w-8 text-blue-500" />
      </div>
      <div className="mt-4 text-sm text-gray-500">
        Events processed in the last 24 hours
      </div>
    </div>
  );
};
