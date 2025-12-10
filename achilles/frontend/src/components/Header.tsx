import { Link } from 'react-router-dom';
import { useTheme } from '../hooks/useTheme';
import { Moon, Sun, Target, Settings, RefreshCw } from 'lucide-react';

interface HeaderProps {
  onSettingsClick?: () => void;
  onRefreshClick?: () => void;
  isRefreshing?: boolean;
}

export default function Header({ onSettingsClick, onRefreshClick, isRefreshing }: HeaderProps) {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-20 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto h-full px-4 flex items-center justify-between">
        {/* Logo and Title */}
        <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
          <div className="flex items-center justify-center w-16 h-16 rounded-lg bg-primary/10">
            <Target className="w-12 h-12 text-primary" />
          </div>
          <div>
            <h1 className="text-4xl font-bold tracking-tight">ACHILLES</h1>
            <p className="text-sm text-muted-foreground">Test Results Visualizer</p>
          </div>
        </Link>

        {/* Actions */}
        <div className="flex items-center gap-2">
          {/* Refresh Button */}
          {onRefreshClick && (
            <button
              onClick={onRefreshClick}
              disabled={isRefreshing}
              className="p-2 rounded-lg hover:bg-accent transition-colors disabled:opacity-50"
              aria-label="Refresh data"
              title="Refresh data"
            >
              <RefreshCw className={`w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          )}

          {/* Settings Button */}
          {onSettingsClick && (
            <button
              onClick={onSettingsClick}
              className="p-2 rounded-lg hover:bg-accent transition-colors"
              aria-label="Settings"
              title="Settings"
            >
              <Settings className="w-5 h-5" />
            </button>
          )}

          {/* Theme Toggle */}
          <button
            onClick={toggleTheme}
            className="p-2 rounded-lg hover:bg-accent transition-colors"
            aria-label="Toggle theme"
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? (
              <Sun className="w-5 h-5" />
            ) : (
              <Moon className="w-5 h-5" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
