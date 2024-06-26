#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <memory>

using namespace std;

// Abstract base class for criteria
class ICriteria {
public:
    virtual bool check(const string& password) const = 0;
    virtual string getMessage() const = 0;
    virtual ~ICriteria() = default;
};

// Concrete classes for each criterion
class MinimumLengthCriteria : public ICriteria {
public:
    bool check(const string& password) const override {
        return password.length() >= 8;
    }

    string getMessage() const override {
        return "Password must be at least 8 characters long.";
    }
};

class UppercaseCriteria : public ICriteria {
public:
    bool check(const string& password) const override {
        return any_of(password.begin(), password.end(), ::isupper);
    }

    string getMessage() const override {
        return "Password must contain at least one uppercase letter.";
    }
};

class LowercaseCriteria : public ICriteria {
public:
    bool check(const string& password) const override {
        return any_of(password.begin(), password.end(), ::islower);
    }

    string getMessage() const override {
        return "Password must contain at least one lowercase letter.";
    }
};

class DigitCriteria : public ICriteria {
public:
    bool check(const string& password) const override {
        return any_of(password.begin(), password.end(), ::isdigit);
    }

    string getMessage() const override {
        return "Password must contain at least one digit.";
    }
};

class SpecialCharCriteria : public ICriteria {
public:
    bool check(const string& password) const override {
        return any_of(password.begin(), password.end(), ::ispunct);
    }

    string getMessage() const override {
        return "Password must contain at least one special character.";
    }
};

class PasswordFeedback {
public:
    string message;
    bool isStrong;

    PasswordFeedback(const string& msg, bool strength) : message(msg), isStrong(strength) {}

    void displayFeedback() const {
        cout << message << endl;
    }
};

class PasswordStrengthChecker {
private:
    string password;
    vector<unique_ptr<ICriteria>> criteriaList;

public:
    PasswordStrengthChecker(const string& pwd) : password(pwd) {
        criteriaList.push_back(make_unique<MinimumLengthCriteria>());
        criteriaList.push_back(make_unique<UppercaseCriteria>());
        criteriaList.push_back(make_unique<LowercaseCriteria>());
        criteriaList.push_back(make_unique<DigitCriteria>());
        criteriaList.push_back(make_unique<SpecialCharCriteria>());
    }

    PasswordFeedback assessStrength() const {
        vector<string> feedback;

        for (const auto& criteria : criteriaList) {
            if (!criteria->check(password)) {
                feedback.push_back(criteria->getMessage());
            }
        }

        if (feedback.empty()) {
            return PasswordFeedback("Password is strong.", true);
        } else {
            string combinedFeedback = "Password is weak. Please address the following issues:\n";
            for (const auto& msg : feedback) {
                combinedFeedback += "- " + msg + "\n";
            }
            return PasswordFeedback(combinedFeedback, false);
        }
    }
};

int main() {
    string password;
    cout << "Enter a password to check its strength: ";
    cin >> password;

    PasswordStrengthChecker checker(password);
    PasswordFeedback feedback = checker.assessStrength();
    feedback.displayFeedback();

    return 0;
}
