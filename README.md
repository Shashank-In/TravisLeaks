# TravisLeaks
A tool to find sensitive keys and passwords in Travis logs

# Description
I wrote a blog post for this tool.


Just enter the Travis user name of the organization. The script will automatically find out all jobs and then do two things.
1) Look for ED's keywords for potential leaks
2) Use the concept of entropy to find potential API keys in the logs 


# Requirements
1)Python 3.X
2)requests
```pip install requests```

# Instructions
python travisleak.py travis_user_name


Credits:-
The keywords for the potential leak was taken from ED's blog post 
https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/

The concept of entropy was adapted from 
https://github.com/dxa4481/truffleHog


# Note:- This tool still needs a lot of development. I would be glad if someone would like to contribute to this project.
