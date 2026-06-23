'use client';

import React, { useMemo } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  ChartOptions,
} from 'chart.js';
import type { ScanReport } from '@/types/scan';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface TrendsChartProps {
  reports: ScanReport[];
  groupBy: 'project' | 'none';
}

function formatDate(value?: string | null) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

const COLORS = ['#10b981', '#60a5fa', '#f59e0b', '#ef4444', '#8a8a80', '#38c46a'];

export function TrendsChart({ reports, groupBy }: TrendsChartProps) {
  const chartData = useMemo(() => {
    const toPoint = (report: ScanReport) => {
      const rawDate = report.created_at || report.timestamp || '';
      const time = new Date(rawDate).getTime();
      return {
        label: formatDate(rawDate),
        time: Number.isNaN(time) ? 0 : time,
        score: Number(report.safety_score || 0),
        project: report.project_name || 'Unlabeled',
      };
    };

    if (groupBy === 'project') {
      const grouped = reports.reduce<Record<string, ReturnType<typeof toPoint>[]>>((acc, report) => {
        const point = toPoint(report);
        acc[point.project] = acc[point.project] || [];
        acc[point.project].push(point);
        return acc;
      }, {});

      const labels = Array.from(new Set(Object.values(grouped).flat().sort((a, b) => a.time - b.time).map((point) => point.label)));
      const datasets = Object.entries(grouped).map(([project, points], index) => {
        const byLabel = new Map(points.map((point) => [point.label, point.score]));
        return {
          label: project,
          data: labels.map((label) => byLabel.get(label) ?? null),
          borderColor: COLORS[index % COLORS.length],
          backgroundColor: COLORS[index % COLORS.length] + '22',
          tension: 0.32,
          fill: true,
          pointRadius: 4,
          pointHoverRadius: 6,
        };
      });
      return { labels, datasets };
    }

    const points = reports.map(toPoint).sort((a, b) => a.time - b.time);
    return {
      labels: points.map((point) => point.label),
      datasets: [{
        label: 'Safety score',
        data: points.map((point) => point.score),
        borderColor: '#10b981',
        backgroundColor: 'rgba(16, 185, 129, 0.15)',
        tension: 0.28,
        fill: true,
        pointRadius: 4,
        pointHoverRadius: 6,
      }],
    };
  }, [reports, groupBy]);

  const options: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          boxWidth: 12,
          padding: 15,
          color: 'rgba(242, 242, 237, 0.68)',
          font: { size: 10, family: 'Inter, sans-serif' }
        }
      },
      tooltip: {
        backgroundColor: 'rgba(17, 23, 21, 0.96)',
        titleColor: '#f2f2ed',
        bodyColor: '#f2f2ed',
        borderColor: 'rgba(255, 255, 255, 0.11)',
        borderWidth: 1,
        padding: 10,
        displayColors: true
      }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: 'rgba(242, 242, 237, 0.44)', font: { size: 9 }, maxRotation: 0 }
      },
      y: {
        min: 0,
        max: 100,
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { stepSize: 20, color: 'rgba(242, 242, 237, 0.44)', font: { size: 9 } }
      }
    }
  };

  return <Line data={chartData} options={options} />;
}
