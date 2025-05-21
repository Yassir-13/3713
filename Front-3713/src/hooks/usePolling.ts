// src/hooks/usePolling.ts
import { useState, useEffect, useCallback } from 'react';

interface PollingOptions {
  initialInterval?: number;
  maxInterval?: number;
  backoffFactor?: number;
  maxAttempts?: number;
  errorThreshold?: number;
}

export function usePolling<T>(
  fetchFunction: () => Promise<T>,
  isActive: boolean,
  onSuccess: (data: T) => boolean, // Return true to continue polling, false to stop
  options?: PollingOptions
) {
  const [attempts, setAttempts] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [currentInterval, setCurrentInterval] = useState<number>(0);
  
  const {
    initialInterval = 2000,
    maxInterval = 30000,
    backoffFactor = 1.5,
    maxAttempts = 180,
    errorThreshold = 3
  } = options || {};

  const poll = useCallback(() => {
    if (!isActive) return () => {};
    
    let timeoutId: number | null = null;
    let consecutiveErrors = 0;
    let pollInterval = initialInterval;
    setCurrentInterval(initialInterval);
    
    const executePoll = async () => {
      if (!isActive) return;
      
      try {
        setAttempts(prev => prev + 1);
        const data = await fetchFunction();
        
        // Reset error counter on success
        consecutiveErrors = 0;
        setError(null);
        
        // If onSuccess returns false, stop polling
        const shouldContinue = onSuccess(data);
        
        if (!shouldContinue || attempts >= maxAttempts) {
          return; // Stop polling
        }
        
        // Continue polling
        timeoutId = window.setTimeout(executePoll, pollInterval);
      } catch (err: any) {
        consecutiveErrors++;
        
        // Only set visible error after multiple failures
        if (consecutiveErrors % 5 === 0) {
          setError(`Connection issue: ${err.message}. We'll keep trying...`);
        }
        
        // Increase interval after consecutive errors
        if (consecutiveErrors >= errorThreshold) {
          pollInterval = Math.min(pollInterval * backoffFactor, maxInterval);
          setCurrentInterval(pollInterval);
          consecutiveErrors = 0; // Reset after increasing interval
        }
        
        // Continue polling even with errors
        timeoutId = window.setTimeout(executePoll, pollInterval);
      }
    };
    
    // Start polling immediately
    executePoll();
    
    // Cleanup function
    return () => {
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
    };
  }, [isActive, fetchFunction, onSuccess, initialInterval, maxInterval, backoffFactor, maxAttempts, errorThreshold, attempts]);
  
  useEffect(() => {
    const cleanup = poll();
    return cleanup;
  }, [poll]);
  
  return { attempts, error, currentInterval };
}