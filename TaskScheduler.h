// TaskScheduler.h
#ifndef TASK_SCHEDULER_H
#define TASK_SCHEDULER_H

#include <Arduino.h>
#include <functional>
#include <vector>

class TaskScheduler {
public:
    using TaskCallback = std::function<void(void)>;
    
    struct Task {
        TaskCallback callback;     // Function to call when task runs
        uint32_t interval;         // Interval in milliseconds between executions
        uint32_t lastRunTime;      // Last time the task was executed
        bool enabled;              // Whether the task is active
        bool runOnce;              // If true, the task runs only once then disables
        const char* name;          // Task name for debugging (optional)
        
        Task(TaskCallback cb, uint32_t ms, bool enabled = true, bool once = false, const char* taskName = nullptr)
            : callback(cb), interval(ms), lastRunTime(0), enabled(enabled), runOnce(once), name(taskName) {}
    };

    TaskScheduler() = default;
    ~TaskScheduler() = default;
    
    // Move semantics for memory safety and performance
    TaskScheduler(TaskScheduler&& other) = default;
    TaskScheduler& operator=(TaskScheduler&& other) = default;
    
    // Delete copy operations to enforce ownership semantics
    TaskScheduler(const TaskScheduler&) = delete;
    TaskScheduler& operator=(const TaskScheduler&) = delete;

    /**
     * Add a task to the scheduler
     * 
     * @param callback Function to call
     * @param interval Time in milliseconds between executions
     * @param enabled Whether the task starts enabled
     * @param runOnce Whether the task runs only once
     * @param name Optional name for debugging
     * @return Index of the task (can be used to reference it later)
     */
    size_t addTask(TaskCallback callback, uint32_t interval, 
                   bool enabled = true, bool runOnce = false, 
                   const char* name = nullptr) {
        _tasks.emplace_back(callback, interval, enabled, runOnce, name);
        return _tasks.size() - 1;
    }
    
    /**
     * Execute scheduled tasks that are due
     * Call this method in your loop()
     */
    void execute() {
        uint32_t currentMillis = millis();
        
        for (auto& task : _tasks) {
            if (!task.enabled) continue;
            
            uint32_t elapsed = currentMillis - task.lastRunTime;
            
            // Handle millis() overflow
            if (elapsed >= task.interval) {
                task.lastRunTime = currentMillis;
                
                // Run the task
                task.callback();
                
                // Disable if it's a one-time task
                if (task.runOnce) {
                    task.enabled = false;
                }
            }
        }
    }
    
    /**
     * Enable a task by its index
     */
    bool enableTask(size_t taskIndex) {
        if (taskIndex < _tasks.size()) {
            _tasks[taskIndex].enabled = true;
            return true;
        }
        return false;
    }
    
    /**
     * Disable a task by its index
     */
    bool disableTask(size_t taskIndex) {
        if (taskIndex < _tasks.size()) {
            _tasks[taskIndex].enabled = false;
            return true;
        }
        return false;
    }
    
    /**
     * Change the interval of a task
     */
    bool setTaskInterval(size_t taskIndex, uint32_t newInterval) {
        if (taskIndex < _tasks.size()) {
            _tasks[taskIndex].interval = newInterval;
            return true;
        }
        return false;
    }
    
    /**
     * Reset a task's timing as if it just executed
     */
    bool resetTask(size_t taskIndex) {
        if (taskIndex < _tasks.size()) {
            _tasks[taskIndex].lastRunTime = millis();
            return true;
        }
        return false;
    }
    
    /**
     * Remove all tasks
     */
    void clear() {
        _tasks.clear();
    }
    
    /**
     * Get number of registered tasks
     */
    size_t size() const {
        return _tasks.size();
    }
    
    /**
     * Run a task immediately and reset its timer
     */
    bool runTaskNow(size_t taskIndex) {
        if (taskIndex < _tasks.size()) {
            _tasks[taskIndex].callback();
            _tasks[taskIndex].lastRunTime = millis();
            if (_tasks[taskIndex].runOnce) {
                _tasks[taskIndex].enabled = false;
            }
            return true;
        }
        return false;
    }
    
    /**
     * Get remaining time until task will run in milliseconds
     */
    int32_t getTaskTimeRemaining(size_t taskIndex) const {
        if (taskIndex < _tasks.size()) {
            const Task& task = _tasks[taskIndex];
            if (!task.enabled) return -1;
            
            uint32_t currentMillis = millis();
            uint32_t elapsed = currentMillis - task.lastRunTime;
            
            if (elapsed >= task.interval) {
                return 0;
            } else {
                return task.interval - elapsed;
            }
        }
        return -1;
    }
    
    /**
     * Find task index by name
     * Returns -1 if not found
     */
    int findTaskByName(const char* name) const {
        if (!name) return -1;
        
        for (size_t i = 0; i < _tasks.size(); i++) {
            if (_tasks[i].name && strcmp(_tasks[i].name, name) == 0) {
                return i;
            }
        }
        return -1;
    }

private:
    std::vector<Task> _tasks;
};

#endif // TASK_SCHEDULER_H