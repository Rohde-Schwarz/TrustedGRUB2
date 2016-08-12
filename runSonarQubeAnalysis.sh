#!/bin/sh
# Exit on failure
set -e

installBuildWrapper() {
  curl -LsS https://sonarqube.com/static/cpp/build-wrapper-linux-x86.zip > build-wrapper-linux-x86.zip
  unzip build-wrapper-linux-x86.zip
}

build() {
  # triggers the compilation through the build wrapper to gather compilation database
  make distclean && ./autogen.sh && ./configure --target=i386 -with-platform=pc
  ./build-wrapper-linux-x86/build-wrapper-linux-x86-64 --out-dir bw-outputs make ${DEFINES} -j 2
}

# run the analysis
if [ "$TRAVIS_BRANCH" = "master" ] && [ "$TRAVIS_PULL_REQUEST" = "false" ] && [ "$SONARQUBE" = "TRUE" ]; then
	# => This will run a full analysis of the project and push results to the SonarQube server.
	#
	# Analysis is done only on master so that build of branches don't push analyses to the same project and therefore "pollute" the results
	echo "Starting analysis by SonarQube..."
	installBuildWrapper
	build
	sonar-scanner -Dsonar.login=$SONAR_TOKEN
elif [ "$TRAVIS_PULL_REQUEST" != "false" ] && [ -n "${GITHUB_TOKEN-}" ]  && [ "$SONARQUBE" = "TRUE" ]; then
	# => This will analyse the PR and display found issues as comments in the PR, but it won't push results to the SonarQube server
	#
	# For security reasons environment variables are not available on the pull requests
	# coming from outside repositories
	# http://docs.travis-ci.com/user/pull-requests/#Security-Restrictions-when-testing-Pull-Requests
	# That's why the analysis does not need to be executed if the variable GITHUB_TOKEN is not defined.
	echo "Starting Pull Request analysis by SonarQube..."
	installBuildWrapper
	build
	sonar-scanner -Dsonar.login=$SONAR_TOKEN \
	-Dsonar.analysis.mode=preview \
	-Dsonar.github.oauth=$GITHUB_TOKEN \
	-Dsonar.github.repository=$TRAVIS_REPO_SLUG \
	-Dsonar.github.pullRequest=$TRAVIS_PULL_REQUEST
fi
# When neither on master branch nor on a non-external pull request => nothing to do
