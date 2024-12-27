#include <stdexcept>

class MissingArgument : public std::invalid_argument {
  public:
    MissingArgument(const std::string& msg) : 
        std::invalid_argument{msg} 
    {
    }
};

class InvalidArgument : public std::invalid_argument {
  public:
    InvalidArgument(const std::string& msg) : 
        std::invalid_argument{msg} 
    {
    }
};

class InvalidKey : public std::invalid_argument {
  public:
    InvalidKey(const std::string& msg) : 
        std::invalid_argument{msg} 
    {
    }
};