#!/usr/bin/perl -w

package main::LogCluster;

sub compile_func {

  my($code) = $_[0];
  my($ret, $error);

  $ret = eval $code;

  if ($@) {
    $error = $@;
    chomp $error;
    return (0, $error);
  } elsif (ref($ret) ne "CODE") {
    return (0, "eval did not return a code reference");
  } else {
    return (1, $ret);
  }
}


package main;

use strict;

no warnings 'recursion';

use vars qw(
  $USAGE
  $aggrsup
  $ansicoloravail
  %candidates
  %clusters
  $color
  $color1
  $color2
  $csize
  @csketch
  $debug
  $facility
  $fpat
  %fword_deps
  %fwords
  %gwords
  $help
  $ifile
  %ifiles
  @inputfilepat
  @inputfiles
  $lcfunc
  $lcfuncptr
  $lfilter
  $lineregexp
  $outlierfile
  %outlierpat
  $progname
  $ptree
  $ptreesize
  $readdump
  $rsupport
  $searchregexp
  $separator
  $sepregexp
  $support
  $syslogavail
  $syslogopen
  $template
  $version
  $wcfunc
  $wcfuncptr
  @weightfunction
  $weightf
  $wfilter
  $wfreq
  $wildcard
  $wordregexp
  $wreplace
  $writedump
  $wsearch
  $wsize
  @wsketch
  $wweight
);

use Getopt::Long;
use Digest::MD5 qw(md5);
use Storable;

$ansicoloravail = eval { require Term::ANSIColor };
$syslogavail = eval { require Sys::Syslog };


######################### Functions #########################

# This function logs the message given with parameter2,..,parameterN to 
# syslog, using the level parameter1. The message is also written to stderr.

sub log_msg {

  my($level) = shift(@_);
  my($msg) = join(" ", @_);

  print STDERR scalar(localtime()), ": $msg\n";
  if ($syslogopen) { Sys::Syslog::syslog($level, $msg); }
}

# This function compiles the function given with parameter1, returning
# a function pointer if the compilation is successful, and undef otherwise

sub compile_func_wrapper {

  my($code) = $_[0];
  my($ok, $value);

  ($ok, $value) = main::LogCluster::compile_func($code);
  if ($ok) { return $value; }
  log_msg("err", "Failed to compile the code '$code':", $value);
  return undef;
}

# This function hashes the string given with parameter1 to an integer
# in the range (0...$wsize-1) and returns the integer. The $wsize integer
# can be set with the --wsize command line option.

sub hash_string {
  return unpack('L', md5($_[0])) % $wsize;
}

# This function hashes the candidate ID given with parameter1 to an integer
# in the range (0...$csize-1) and returns the integer. The $csize integer
# can be set with the --csize command line option.

sub hash_candidate {
  return unpack('L', md5($_[0])) % $csize;
}

# This function matches the line given with parameter1 with a regular
# expression $lineregexp (the expression can be set with the --lfilter
# command line option). If the $template string is defined (can be set
# with the --template command line option), the line is converted 
# according to $template (match variables in $template are substituted
# with values from regular expression match, and the resulting string
# replaces the line). If the regular expression $lineregexp does not match
# the line, 0 is returned, otherwise the line (or converted line, if
# --template option has been given) is returned.
# If the --lfilter option has not been given but --lcfunc option is
# present, the Perl function given with --lcfunc is used for matching
# and converting the line. If the function returns 'undef', line is
# regarded non-matching, otherwise the value returned by the function
# replaces the original line.
# If neither --lfilter nor --lcfunc option has been given, the line
# is returned without a trailing newline.

sub process_line {

  my($line) = $_[0];
  my(%matches, @matches, $match, $i);

  chomp($line);

  if (defined($lfilter)) {

    if (!defined($template)) {
      if ($line =~ /$lineregexp/) { return $line; } else { return undef; }
    }

    if (@matches = ($line =~ /$lineregexp/)) {
      %matches = %+;
      $matches{"0"} = $line;
      $i = 1;
      foreach $match (@matches) { $matches{$i++} = $match; }
      $line = $template;
      $line =~ s/\$(?:\$|(\d+)|\{(\d+)\}|\+\{(\w+)\})/
               !defined($+)?'$':(defined($matches{$+})?$matches{$+}:'')/egx;
      return $line;
    }

    return undef;

  } elsif (defined($lcfunc)) {

    $line = eval { $lcfuncptr->($line) };
    return $line;

  } else {
    return $line;
  }
}

# This function makes a pass over the data set and builds the sketch 
# @wsketch which is used for finding frequent words. The sketch contains 
# $wsize counters ($wsize can be set with --wsize command line option).

sub build_word_sketch {

  my($index, $ifile, $line, $word, $word2, $i);
  my(@words, @words2, %words);

  for ($index = 0; $index < $wsize; ++$index) { $wsketch[$index] = 0; }

  $i = 0;

  foreach $ifile (@inputfiles) {

    if (!open(FILE, $ifile)) {
      log_msg("err", "Can't open input file $ifile: $!");
      exit(1);
    }

    while (<FILE>) {
      $line = process_line($_);
      if (!defined($line)) { next; }
      ++$i;
      @words = split(/$sepregexp/, $line);
      %words = map { $_ => 1 } @words;
      @words = keys %words;
      foreach $word (@words) {
        $index = hash_string($word); 
        ++$wsketch[$index]; 
        if (defined($wfilter) && $word =~ /$wordregexp/) {
          $word =~ s/$searchregexp/$wreplace/g;
          $index = hash_string($word);
          ++$wsketch[$index];
        } elsif (defined($wcfunc)) {
          @words2 = eval { $wcfuncptr->($word) };
          foreach $word2 (@words2) { 
            if (!defined($word2)) { next; }
            $index = hash_string($word2);
            ++$wsketch[$index];
          }
        }
      }
    }

    close(FILE);
  }

  if (!defined($support)) { 
    $support = int($rsupport * $i / 100); 
    log_msg("info", "Total $i lines read from input sources, using absolute support $support (relative support $rsupport percent)");
  }

  $i = 0;
  for ($index = 0; $index < $wsize; ++$index) {
    if ($wsketch[$index] >= $support) { ++$i; }
  }

  log_msg("info", "Word sketch successfully built, $i buckets >= $support");
}

# This function makes a pass over the data set, finds frequent words and 
# stores them to %fwords hash table.

sub find_frequent_words {

  my($ifile, $line, $word, $word2, $index, $i);
  my(@words, @words2, %words);

  $i = 0;

  foreach $ifile (@inputfiles) {

    if (!open(FILE, $ifile)) {
      log_msg("err", "Can't open input file $ifile: $!");
      exit(1);
    }

    while (<FILE>) {
      $line = process_line($_);
      if (!defined($line)) { next; }
      ++$i;
      @words = split(/$sepregexp/, $line);
      %words = map { $_ => 1 } @words;
      @words = keys %words;
      if (defined($wsize)) {
        foreach $word (@words) {
          $index = hash_string($word);
          if ($wsketch[$index] >= $support) { ++$fwords{$word}; }
          if (defined($wfilter) && $word =~ /$wordregexp/) {
            $word =~ s/$searchregexp/$wreplace/g;
            $index = hash_string($word);
            if ($wsketch[$index] >= $support) { ++$fwords{$word}; }
          } elsif (defined($wcfunc)) {
            @words2 = eval { $wcfuncptr->($word) };
            foreach $word2 (@words2) { 
              if (!defined($word2)) { next; }
              $index = hash_string($word2);
              if ($wsketch[$index] >= $support) { ++$fwords{$word2}; }
            }
          }
        }
      } else {
        foreach $word (@words) { 
          ++$fwords{$word}; 
          if (defined($wfilter) && $word =~ /$wordregexp/) {
            $word =~ s/$searchregexp/$wreplace/g;
            ++$fwords{$word};
          } elsif (defined($wcfunc)) {
            @words2 = eval { $wcfuncptr->($word) };
            foreach $word2 (@words2) { 
              if (!defined($word2)) { next; }
              ++$fwords{$word2}; 
            }
          }
        }
      }
    }

    close(FILE);
  }

  if (!defined($support)) { 
    $support = int($rsupport * $i / 100); 
    log_msg("info", "Total $i lines read from input sources, using absolute support $support (relative support $rsupport percent)");
  }

  foreach $word (keys %fwords) {
    if ($fwords{$word} < $support) { delete $fwords{$word}; }
  }

  if ($debug) {
    foreach $word (sort { $fwords{$b} <=> $fwords{$a} } keys %fwords) {
      log_msg("debug", "Frequent word: $word -- occurs in", 
                       $fwords{$word}, "lines");
    }
  }

  log_msg("info", "Total number of frequent words:", scalar(keys %fwords));
}

# This function makes a pass over the data set and builds the sketch 
# @csketch which is used for finding frequent candidates. The sketch contains 
# $csize counters ($csize can be set with --csize command line option).

sub build_candidate_sketch {

  my($ifile, $line, $word, $word2, $candidate, $index, $i);
  my(@words, @words2, @candidate);

  for ($index = 0; $index < $csize; ++$index) { $csketch[$index] = 0; }

  foreach $ifile (@inputfiles) {

    if (!open(FILE, $ifile)) {
      log_msg("err", "Can't open input file $ifile: $!");
      exit(1);
    }

    while (<FILE>) {

      $line = process_line($_);
      if (!defined($line)) { next; }

      @words = split(/$sepregexp/, $line);
      @candidate = ();

      foreach $word (@words) {
        if (exists($fwords{$word})) { 
          push @candidate, $word; 
        } elsif (defined($wfilter) && $word =~ /$wordregexp/) {
          $word =~ s/$searchregexp/$wreplace/g;
          if (exists($fwords{$word})) { 
            push @candidate, $word; 
          } 
        } elsif (defined($wcfunc)) {
          @words2 = eval { $wcfuncptr->($word) };
          foreach $word2 (@words2) { 
            if (!defined($word2)) { next; }
            if (exists($fwords{$word2})) { 
              push @candidate, $word2; 
              last;
            }
          }
        }
      }

      if (scalar(@candidate)) {
        $candidate = join("\n", @candidate);
        $index = hash_candidate($candidate);
        ++$csketch[$index];
      }
    }

    close(FILE);
  }

  $i = 0;
  for ($index = 0; $index < $csize; ++$index) {
    if ($csketch[$index] >= $support) { ++$i; }
  }

  log_msg("info", "Candidate sketch successfully built, $i buckets >= $support");
}

# This function logs the description for candidate parameter1.

sub print_candidate {

  my($candidate) = $_[0];
  my($i, $msg);
  
  $msg = "Cluster candidate with support " . 
         $candidates{$candidate}->{"Count"} . ": ";

  for ($i = 0; $i < $candidates{$candidate}->{"WordCount"}; ++$i) {
    if ($candidates{$candidate}->{"Vars"}->[$i]->[1] > 0) {
      $msg .= "*{" . $candidates{$candidate}->{"Vars"}->[$i]->[0] . "," . 
                     $candidates{$candidate}->{"Vars"}->[$i]->[1] . "} ";
    }
    $msg .= $candidates{$candidate}->{"Words"}->[$i] . " ";
  }

  if ($candidates{$candidate}->{"Vars"}->[$i]->[1] > 0) {
      $msg .= "*{" . $candidates{$candidate}->{"Vars"}->[$i]->[0] . "," . 
              $candidates{$candidate}->{"Vars"}->[$i]->[1] . "}";
  }

  log_msg("debug", $msg);
}

# This function makes a pass over the data set, identifies cluster candidates
# and stores them to %candidates hash table. If the --wweight command line
# option has been provided, dependencies between frequent words are also
# identified during the data pass and stored to %fword_deps hash table.

sub find_candidates {

  my($ifile, $line, $word, $word2, $varnum, $candidate, $index, $total, $i);
  my(@words, @words2, %words, @candidate, @vars);

  foreach $ifile (@inputfiles) {

    if (!open(FILE, $ifile)) {
      log_msg("err", "Can't open input file $ifile: $!");
      exit(1);
    }

    while (<FILE>) {

      $line = process_line($_);
      if (!defined($line)) { next; }

      @words = split(/$sepregexp/, $line);
      @candidate = ();
      @vars = ();
      $varnum = 0;

      foreach $word (@words) {
        if (exists($fwords{$word})) { 
          push @candidate, $word; 
          push @vars, $varnum;
          $varnum = 0;
        } elsif (defined($wfilter) && $word =~ /$wordregexp/) {
          $word =~ s/$searchregexp/$wreplace/g;
          if (exists($fwords{$word})) {
            push @candidate, $word;
            push @vars, $varnum;
            $varnum = 0;
          } else {
            ++$varnum;
          }
        } elsif (defined($wcfunc)) {
          @words2 = eval { $wcfuncptr->($word) };
          $i = 0;
          foreach $word2 (@words2) {
            if (!defined($word2)) { next; }
            if (exists($fwords{$word2})) {
              push @candidate, $word2;
              push @vars, $varnum;
              $varnum = 0;
              $i = 1;
              last;
            }
          }
          if (!$i) { ++$varnum; }
        } else {
          ++$varnum;
        }
      }
      push @vars, $varnum;

      if (scalar(@candidate)) {

        $candidate = join("\n", @candidate);

        # if the candidate sketch has been created previously, check the
        # sketch bucket that corresponds to the candidate, and if it is
        # smaller than support threshold, don't consider the candidate

        if (defined($csize)) {
          $index = hash_candidate($candidate);
          if ($csketch[$index] < $support) { next; }
        }

        # if --wweight option was given, store word dependency information
        # (word co-occurrence counts) to %fword_deps

        if (defined($wweight)) {
          %words = map { $_ => 1 } @candidate;
          @words = keys %words;
          foreach $word (@words) {
            foreach $word2 (@words) { ++$fword_deps{$word}->{$word2}; }
          }
        }

        # if the given candidate already exists, increase its support and
        # adjust its wildcard information, otherwise create a new candidate

        if (!exists($candidates{$candidate})) {
          $candidates{$candidate} = {};
          $candidates{$candidate}->{"Words"} = [ @candidate ];
          $candidates{$candidate}->{"WordCount"} = scalar(@candidate);
          $candidates{$candidate}->{"Vars"} = [];
          for $varnum (@vars) {
            push @{$candidates{$candidate}->{"Vars"}}, [ $varnum, $varnum];
          }
          $candidates{$candidate}->{"Count"} = 1;
        } else {
          $total = scalar(@vars);
          for ($index = 0; $index < $total; ++$index) {
            if ($candidates{$candidate}->{"Vars"}->[$index]->[0] 
                > $vars[$index]) {
              $candidates{$candidate}->{"Vars"}->[$index]->[0] = $vars[$index];
            }
            elsif ($candidates{$candidate}->{"Vars"}->[$index]->[1] 
                   < $vars[$index]) {
              $candidates{$candidate}->{"Vars"}->[$index]->[1] = $vars[$index];
            }
          }
          ++$candidates{$candidate}->{"Count"};
        }
      }
    }

    close(FILE);
  }

  # if --wweight option was given, convert word dependency information
  # (word co-occurrence counts) into range 0..1

  if (defined($wweight)) {
    $i = 0;
    foreach $word (keys %fwords) { 
      foreach $word2 (keys %{$fword_deps{$word}}) {
        $fword_deps{$word}->{$word2} /= $fwords{$word};
        ++$i;
        if ($debug) {
          log_msg("debug", "Dependency $word -> $word2:", 
                           $fword_deps{$word}->{$word2});
        }
      } 
    }
    log_msg("info", "Total number of frequent word dependencies:", $i);
  }

  if ($debug) {
    foreach $candidate (sort { $candidates{$b}->{"Count"} <=>
                               $candidates{$a}->{"Count"} } keys %candidates) {
      print_candidate($candidate);
    }
  }

  log_msg("info", "Total number of candidates:", scalar(keys %candidates));
}

# This function finds frequent candidates by removing candidates with
# insufficient support from the %candidates hash table.

sub find_frequent_candidates {

  my($candidate);

  foreach $candidate (keys %candidates) {
    if ($candidates{$candidate}->{"Count"} < $support) { 
      delete $candidates{$candidate}; 
    }
  }

  log_msg("info", "Total number of frequent candidates:", 
                   scalar(keys %candidates));
}

# This function inserts a candidate into the prefix tree

sub insert_into_prefix_tree {

  my($node, $cand, $i) = @_;
  my($label);

  if ($i == $candidates{$cand}->{"WordCount"}) {
    $label = $candidates{$cand}->{"Vars"}->[$i]->[0] . "\n" .
             $candidates{$cand}->{"Vars"}->[$i]->[1];
  } else {
    $label = $candidates{$cand}->{"Vars"}->[$i]->[0] . "\n" .
             $candidates{$cand}->{"Vars"}->[$i]->[1] . "\n" .
             $candidates{$cand}->{"Words"}->[$i];
  }

  if (!exists($node->{"Children"}->{$label})) {
    $node->{"Children"}->{$label} = {};
    $node = $node->{"Children"}->{$label};
    $node->{"Min"} = $candidates{$cand}->{"Vars"}->[$i]->[0];
    $node->{"Max"} = $candidates{$cand}->{"Vars"}->[$i]->[1];

    if ($i < $candidates{$cand}->{"WordCount"}) {
      $node->{"Children"} = {};
      $node->{"Word"} = $candidates{$cand}->{"Words"}->[$i];
    } else {
      $node->{"Candidate"} = $cand;
    }
    ++$ptreesize;

  } else {
    $node = $node->{"Children"}->{$label};
  }

  if ($i < $candidates{$cand}->{"WordCount"}) {
    insert_into_prefix_tree($node, $cand, $i + 1);
  }
}

# This function arranges all candidates into the prefix tree data structure,
# in order to facilitate fast matching between candidates

sub build_prefix_tree {

  my($cand);

  $ptree = { Children => {} };
  $ptreesize = 0;

  foreach $cand (keys %candidates) {
    insert_into_prefix_tree($ptree, $cand, 0);
  }

  log_msg("info", "Total number of nodes in prefix tree:", $ptreesize);
}

# This function finds more specific candidates for the given candidate with
# the help of the prefix tree, and records more specific candidates into
# the SubClusters hash table of the given candidate

sub find_more_specific {

  my($node, $cand, $i, $min, $max) = @_;
  my($candidate, $children, $child, $cand2);
  my($candmin, $candmax);

  $candidate = $candidates{$cand};
  $candmin = $candidate->{"Vars"}->[$i]->[0];
  $candmax = $candidate->{"Vars"}->[$i]->[1];
  $children = $node->{"Children"};

  foreach $child (keys %{$children}) {

    $node = $children->{$child};

    if ($i == $candidate->{"WordCount"}) {
      if (exists($node->{"Candidate"})) {
        if ($candmin > $node->{"Min"} + $min || 
            $candmax < $node->{"Max"} + $max) { next; }
        $cand2 = $node->{"Candidate"};
        if ($cand ne $cand2) {
          $candidate->{"SubClusters"}->{$cand2} = 1;
        }
      } else {
        find_more_specific($node, $cand, $i, $min + $node->{"Min"} + 1,
                                             $max + $node->{"Max"} + 1);
      }
      next;
    }

    if (exists($node->{"Candidate"})) { next; }
    if ($candmax < $node->{"Max"} + $max) { next; }

    if ($candmin > $node->{"Min"} + $min || 
        $candidate->{"Words"}->[$i] ne $node->{"Word"}) { 
      find_more_specific($node, $cand, $i, $min + $node->{"Min"} + 1,
                                           $max + $node->{"Max"} + 1);
      next;
    }

    find_more_specific($node, $cand, $i + 1, 0, 0);

    find_more_specific($node, $cand, $i, $min + $node->{"Min"} + 1,
                                         $max + $node->{"Max"} + 1);
  }
}

# This function scans all cluster candidates (stored in %candidates hash
# table), and for each candidate X it finds all candidates Y1,..,Yk which
# represent more specific line patterns. After finding such clusters Yi
# for each X, the supports of Yi are added to the support of each X. 
# For speeding up the process, previously created prefix tree is used.
# In order to facilitate the detection of outliers, for each X with sufficient
# support the clusters Yi are stored to %outlierpat hash table (this allows
# for fast detection of non-outliers which match X).

sub aggregate_supports {

  my(@keys, @keys2, $cand, $cand2);

  @keys = keys %candidates;

  foreach $cand (@keys) { 

    $candidates{$cand}->{"OldCount"} = $candidates{$cand}->{"Count"};
    $candidates{$cand}->{"Count2"} = $candidates{$cand}->{"Count"};
    $candidates{$cand}->{"SubClusters"} = {};

    find_more_specific($ptree, $cand, 0, 0, 0);
    @keys2 = keys %{$candidates{$cand}->{"SubClusters"}};

    foreach $cand2 (@keys2) {
      $candidates{$cand}->{"Count2"} += $candidates{$cand2}->{"Count"};
    }
  }

  foreach $cand (@keys) {

    $candidates{$cand}->{"Count"} = $candidates{$cand}->{"Count2"};
    @keys2 = keys %{$candidates{$cand}->{"SubClusters"}};

    if (scalar(@keys2)) {

      if (defined($outlierfile) && $candidates{$cand}->{"Count"} >= $support) {
        foreach $cand2 (@keys2) { $outlierpat{$cand2} = 1; }
      }

      if ($debug) { 
        log_msg("debug", 
                "The support of the following candidate was increased from",
                $candidates{$cand}->{"OldCount"}, "to",
                $candidates{$cand}->{"Count"});
        print_candidate($cand);
        log_msg("debug", "with the following candidates being more specific:");
        foreach $cand2 (@keys2) { 
          print_candidate($cand2); 
          log_msg("debug", "(original support:", 
                           $candidates{$cand2}->{"OldCount"}, ")");
        }
        log_msg("debug", "----------------------------------------");
      }
    }

  }
}

# This function makes a pass over the data set, find outliers and stores them
# to file $outlierfile (can be set with the --outliers command line option).

sub find_outliers {

  my($ifile, $line, $word, $word2, $candidate, $i);
  my(@words, @words2, @candidate);

  if (!open(OUTLIERFILE, ">$outlierfile")) {
    log_msg("err", "Can't open outlier file $outlierfile: $!");
    exit(1);
  }

  $i = 0;

  foreach $ifile (@inputfiles) {

    if (!open(FILE, $ifile)) {
      log_msg("err", "Can't open input file $ifile: $!");
      exit(1);
    }

    while (<FILE>) {

      $line = process_line($_);
      if (!defined($line)) { next; }

      @words = split(/$sepregexp/, $line);
      @candidate = ();

      foreach $word (@words) {
        if (exists($fwords{$word})) { 
          push @candidate, $word; 
        } elsif (defined($wfilter) && $word =~ /$wordregexp/) {
          $word =~ s/$searchregexp/$wreplace/g;
          if (exists($fwords{$word})) {
            push @candidate, $word;
          }
        } elsif (defined($wcfunc)) {
          @words2 = eval { $wcfuncptr->($word) };
          foreach $word2 (@words2) {
            if (!defined($word2)) { next; }
            if (exists($fwords{$word2})) {
              push @candidate, $word2;
              last;
            }
          }
        }
      }

      if (scalar(@candidate)) {
        $candidate = join("\n", @candidate);
        if (exists($candidates{$candidate})) { next; }
        if (defined($aggrsup) && exists($outlierpat{$candidate})) { next; }
      }

      print OUTLIERFILE $_;
      ++$i;
    }

    close(FILE);
  }

  close(OUTLIERFILE);

  log_msg("info", "Total number of outliers:", $i);
}

# This function inspects the cluster candidate parameter1 and finds the weight
# of each word in the candidate description. The weights are calculated from
# word dependency information according to --weightf=1.

sub find_weights {

  my($candidate) = $_[0];
  my($ref, $total, $word, $word2, $weight);

  $ref = $candidates{$candidate}->{"Words"};
  $total = $candidates{$candidate}->{"WordCount"};
  $candidates{$candidate}->{"Weights"} = [];

  foreach $word (@{$ref}) {
    $weight = 0;
    foreach $word2 (@{$ref}) { $weight += $fword_deps{$word2}->{$word}; }
    push @{$candidates{$candidate}->{"Weights"}}, $weight / $total;
  }
}

# This function inspects the cluster candidate parameter1 and finds the weight
# of each word in the candidate description. The weights are calculated from
# word dependency information according to --weightf=2.

sub find_weights2 {

  my($candidate) = $_[0];
  my($ref, $total, $word, $word2);
  my(%weights, @words);

  $ref = $candidates{$candidate}->{"Words"};
  $candidates{$candidate}->{"Weights"} = [];

  %weights = map { $_ => 0 } @{$ref};
  @words = keys %weights;
  $total = scalar(@words) - 1;

  foreach $word (@words) {
    if (!$total) {
      $weights{$word} = 1;
      last;
    }
    foreach $word2 (@words) {
      if ($word eq $word2) { next; } 
      $weights{$word} += $fword_deps{$word2}->{$word};
    }
    $weights{$word} /= $total;
  }

  foreach $word (@{$ref}) {
    push @{$candidates{$candidate}->{"Weights"}}, $weights{$word};
  }
}

# This function inspects the cluster candidate parameter1 and finds the weight
# of each word in the candidate description. The weights are calculated from
# word dependency information according to --weightf=3.

sub find_weights3 {

  my($candidate) = $_[0];
  my($ref, $total, $word, $word2, $weight);

  $ref = $candidates{$candidate}->{"Words"};
  $total = $candidates{$candidate}->{"WordCount"};
  $candidates{$candidate}->{"Weights"} = [];

  foreach $word (@{$ref}) {
    $weight = 0;
    foreach $word2 (@{$ref}) { 
      $weight += ($fword_deps{$word2}->{$word} + $fword_deps{$word}->{$word2}); 
    }
    push @{$candidates{$candidate}->{"Weights"}}, $weight / (2 * $total);
  }
}

# This function inspects the cluster candidate parameter1 and finds the weight
# of each word in the candidate description. The weights are calculated from
# word dependency information according to --weightf=4.

sub find_weights4 {

  my($candidate) = $_[0];
  my($ref, $total, $word, $word2);
  my(%weights, @words);

  $ref = $candidates{$candidate}->{"Words"};
  $candidates{$candidate}->{"Weights"} = [];

  %weights = map { $_ => 0 } @{$ref};
  @words = keys %weights;
  $total = scalar(@words) - 1;

  foreach $word (@words) {
    if (!$total) {
      $weights{$word} = 1;
      last;
    }
    foreach $word2 (@words) {
      if ($word eq $word2) { next; } 
      $weights{$word} += 
          ($fword_deps{$word2}->{$word} + $fword_deps{$word}->{$word2});
    }
    $weights{$word} /= (2 * $total);
  }

  foreach $word (@{$ref}) {
    push @{$candidates{$candidate}->{"Weights"}}, $weights{$word};
  }
}

# This function prints word weights for cluster candidate parameter1.

sub print_weights {

  my($candidate) = $_[0];
  my($i, $msg);
  
  $msg = "Cluster candidate with support " . 
         $candidates{$candidate}->{"Count"} . ": ";

  for ($i = 0; $i < $candidates{$candidate}->{"WordCount"}; ++$i) {
    if ($candidates{$candidate}->{"Vars"}->[$i]->[1] > 0) {
      $msg .= "*{" . $candidates{$candidate}->{"Vars"}->[$i]->[0] . "," . 
                     $candidates{$candidate}->{"Vars"}->[$i]->[1] . "} ";
    }
    $msg .= $candidates{$candidate}->{"Words"}->[$i] .
            " (weight: " . $candidates{$candidate}->{"Weights"}->[$i] . ") ";
  }

  if ($candidates{$candidate}->{"Vars"}->[$i]->[1] > 0) {
      $msg .= "*{" . $candidates{$candidate}->{"Vars"}->[$i]->[0] . "," . 
              $candidates{$candidate}->{"Vars"}->[$i]->[1] . "}";
  }

  log_msg("debug", $msg);
}

# This function joins the cluster candidate parameter1 to a suitable cluster
# by words with insufficient weights. If there is no suitable cluster, 
# a new cluster is created from the candidate.

sub join_candidate {

  my($candidate) = $_[0];
  my($i, $n, $cluster, @words);
  
  $n = $candidates{$candidate}->{"WordCount"};

  for ($i = 0; $i < $n; ++$i) {
    if ($candidates{$candidate}->{"Weights"}->[$i] >= $wweight) {
      push @words, $candidates{$candidate}->{"Words"}->[$i];
    } else {
      push @words, "";
    }
  }

  $cluster = join("\n", @words);

  if (!exists($clusters{$cluster})) {
    $clusters{$cluster} = {};
    $clusters{$cluster}->{"Words"} = 
                               [ map { length($_)?$_:{} } @words ];
    $clusters{$cluster}->{"Vars"} =
                               [ @{$candidates{$candidate}->{"Vars"}} ];
    $clusters{$cluster}->{"WordCount"} = 
                               $candidates{$candidate}->{"WordCount"};
    $clusters{$cluster}->{"Count"} = 0;
  }

  for ($i = 0; $i < $n; ++$i) {
    if (ref($clusters{$cluster}->{"Words"}->[$i]) eq "HASH") {
      $clusters{$cluster}->{"Words"}->[$i]->{$candidates{$candidate}->{"Words"}->[$i]} = 1;
    }
  }

  ++$n;

  for ($i = 0; $i < $n; ++$i) {
    if ($clusters{$cluster}->{"Vars"}->[$i]->[0] >
        $candidates{$candidate}->{"Vars"}->[$i]->[0]) {
      $clusters{$cluster}->{"Vars"}->[$i]->[0] =
      $candidates{$candidate}->{"Vars"}->[$i]->[0];
    }
    if ($clusters{$cluster}->{"Vars"}->[$i]->[1] <
        $candidates{$candidate}->{"Vars"}->[$i]->[1]) {
      $clusters{$cluster}->{"Vars"}->[$i]->[1] =
      $candidates{$candidate}->{"Vars"}->[$i]->[1];
    }
  }

  $clusters{$cluster}->{"Count"} += $candidates{$candidate}->{"Count"};
} 

# This function joins the cluster candidate parameter1 to a suitable cluster
# by words with insufficient weights. If there is no suitable cluster, 
# a new cluster is created from the candidate.

sub join_candidate2 {

  my($candidate) = $_[0];
  my($i, $n, $cluster, @words);
  my($min, $max, @vars);
  
  $n = $candidates{$candidate}->{"WordCount"};
  $min = 0;
  $max = 0;

  for ($i = 0; $i < $n; ++$i) {
    if ($candidates{$candidate}->{"Weights"}->[$i] >= $wweight) {
      push @words, $candidates{$candidate}->{"Words"}->[$i];
      push @vars, [ $candidates{$candidate}->{"Vars"}->[$i]->[0] + $min,
                    $candidates{$candidate}->{"Vars"}->[$i]->[1] + $max ];
      $min = 0;
      $max = 0;
    } else {
      $min += ($candidates{$candidate}->{"Vars"}->[$i]->[0] + 1);
      $max += ($candidates{$candidate}->{"Vars"}->[$i]->[1] + 1);
    }
  }
  push @vars, [ $candidates{$candidate}->{"Vars"}->[$i]->[0] + $min,
                $candidates{$candidate}->{"Vars"}->[$i]->[1] + $max ];

  $cluster = join("\n", @words);

  if (!exists($clusters{$cluster})) {

    $clusters{$cluster} = {};
    $clusters{$cluster}->{"Words"} = [ @words ];
    $clusters{$cluster}->{"Vars"} = [ @vars ];
    $clusters{$cluster}->{"WordCount"} = scalar(@words);
    $clusters{$cluster}->{"Count"} = $candidates{$candidate}->{"Count"};

  } else {

    $n = $clusters{$cluster}->{"WordCount"} + 1;

    for ($i = 0; $i < $n; ++$i) {
      if ($clusters{$cluster}->{"Vars"}->[$i]->[0] > $vars[$i]->[0]) {
        $clusters{$cluster}->{"Vars"}->[$i]->[0] = $vars[$i]->[0];
      }
      if ($clusters{$cluster}->{"Vars"}->[$i]->[1] < $vars[$i]->[1]) {
        $clusters{$cluster}->{"Vars"}->[$i]->[1] = $vars[$i]->[1];
      }
    }

    $clusters{$cluster}->{"Count"} += $candidates{$candidate}->{"Count"};
  }
} 

# This function joins frequent cluster candidates into final clusters
# by words with insufficient weights. For each candidate, word weights
# are first calculated and the candidate is then compared to already
# existing clusters, in order to find a suitable cluster for joining.
# If no such cluster exists, a new cluster is created from the candidate.

sub join_candidates {

  my($candidate);

  foreach $candidate (sort { $candidates{$b}->{"Count"} <=>
                             $candidates{$a}->{"Count"} } keys %candidates) {
    $weightfunction[$weightf]->($candidate);
    if ($debug) { print_weights($candidate); }
    if ($wildcard) { 
      join_candidate2($candidate); 
    } else { 
      join_candidate($candidate);
    }
  }
}

# This function finds frequent words in detected clusters

sub cluster_freq_words {

  my($cluster, $i, $word, %words);
  my($threshold, $total, @keys);

  @keys = keys %clusters;
  $total = scalar(@keys);

  if ($total == 0) { return; }

  foreach $cluster (@keys) {
    %words = ();
    for ($i = 0; $i < $clusters{$cluster}->{"WordCount"}; ++$i) {
      if (ref($clusters{$cluster}->{"Words"}->[$i]) eq "HASH") { next; }
      $words{$clusters{$cluster}->{"Words"}->[$i]} = 1;
    }
    foreach $word (keys %words) { ++$gwords{$word}; }
  }

  $threshold = $total * $wfreq;

  foreach $word (keys %gwords) { 
    if ($gwords{$word} < $threshold) { delete $gwords{$word}; } 
  }
}

# This function prints the cluster parameter1 to standard output.

sub print_cluster {

  my($cluster) = $_[0];
  my($i, $word, @wordlist);
  
  if ($wfreq) { cluster_freq_words(); }

  for ($i = 0; $i < $clusters{$cluster}->{"WordCount"}; ++$i) {
    if ($clusters{$cluster}->{"Vars"}->[$i]->[1] > 0) {
      print "*{" . $clusters{$cluster}->{"Vars"}->[$i]->[0] . "," . 
                   $clusters{$cluster}->{"Vars"}->[$i]->[1] . "}";
      print " ";
    }
    if (ref($clusters{$cluster}->{"Words"}->[$i]) eq "HASH") {
      @wordlist = keys %{$clusters{$cluster}->{"Words"}->[$i]};
      if (scalar(@wordlist) > 1) {
        $word = "(" . join("|", @wordlist) . ")";
        if (defined($color1)) {
          print Term::ANSIColor::color($color1);
          print $word, " ";
          print Term::ANSIColor::color("reset");
        } else {
          print $word, " ";
        }
      } else {
        $word = $wordlist[0];
        if (defined($color1)) {
          print Term::ANSIColor::color($color1);
          print $word, " ";
          print Term::ANSIColor::color("reset");
        } elsif (defined($color2) && exists($gwords{$word})) {
          print Term::ANSIColor::color($color2);
          print $word, " ";
          print Term::ANSIColor::color("reset");
        } else {
          print $word, " ";
        }
      }
    } else {
      $word = $clusters{$cluster}->{"Words"}->[$i];
      if (defined($color2) && exists($gwords{$word})) {
        print Term::ANSIColor::color($color2);
        print $word, " ";
        print Term::ANSIColor::color("reset");
      } else {
        print $word, " ";
      }
    }
  }

  if ($clusters{$cluster}->{"Vars"}->[$i]->[1] > 0) {
      print "*{" . $clusters{$cluster}->{"Vars"}->[$i]->[0] . "," . 
                   $clusters{$cluster}->{"Vars"}->[$i]->[1] . "}";
  }

  print "\n";
  print "Support: ", $clusters{$cluster}->{"Count"};
  print "\n\n";
}

# This function prints all clusters to standard output.

sub print_clusters {

  my($cluster);

  foreach $cluster (sort { $clusters{$b}->{"Count"} <=>
                           $clusters{$a}->{"Count"} } keys %clusters) {
    print_cluster($cluster);
  }

  log_msg("info", "Total number of clusters:", scalar(keys %clusters));
}

######################### Main program #########################

$weightfunction[1] = \&find_weights;
$weightfunction[2] = \&find_weights2;
$weightfunction[3] = \&find_weights3;
$weightfunction[4] = \&find_weights4;


$progname = (split(/\//, $0))[-1];

$USAGE = qq!Usage: $progname [options]
Options:
  --input=<file_pattern> ...
  --support=<support>
 

!;

# if no options are provided in command line, set the --help option
# (check is done before GetOptions() which removes elements from @ARGV)

if (!scalar(@ARGV)) { $help = 1; }

# process command line options

GetOptions( "input=s" => \@inputfilepat,
            "support=i" => \$support,
            "rsupport=f" => \$rsupport,
            "separator=s" => \$separator,
            "lfilter=s" => \$lfilter,
            "template=s" => \$template,
            "lcfunc=s" => \$lcfunc,
            "syslog=s" => \$facility,
            "wsize=i" => \$wsize,
            "csize=i" => \$csize,
            "wweight=f" => \$wweight,
            "weightf=i" => \$weightf,
            "wfreq=f" => \$wfreq,
            "wfilter=s" => \$wfilter,
            "wsearch=s" => \$wsearch,
            "wreplace=s" => \$wreplace,
            "wcfunc=s" => \$wcfunc,
            "outliers=s" => \$outlierfile,
            "readdump=s" => \$readdump,
            "writedump=s" => \$writedump,
            "color:s" => \$color,
            "aggrsup" => \$aggrsup,
            "wildcard" => \$wildcard,
            "debug" => \$debug,
            "help|?" => \$help,
            "version" => \$version );

# print the usage help if requested

if (defined($help)) {
  print $USAGE;
  exit(0);
}

# print the version number if requested

if (defined($version)) {
  print "Lcluster version 0.01\n";
  exit(0);
}

# open connection to syslog with a given facility

if (defined($facility)) {
  if ($syslogavail) { 
    Sys::Syslog::openlog($progname, "pid", $facility);
    $syslogopen = 1;
  }
}

# exit if improper value is given for --wweight option

if (defined($wweight) && ($wweight <= 0 || $wweight > 1)) {
  log_msg("err", "Please specify a positive real number not greater than 1 with --wweight option");
  exit(1);
}

# if --wweight option is given but --weightf is not, set it to default

if (defined($wweight) && !defined($weightf)) {
  $weightf = 1;
}

# exit if improper value is given for --weightf option

if (defined($weightf) && !defined($weightfunction[$weightf])) {
  log_msg("err", "--weightf option does not support function $weightf");
  exit(1);
}

# exit if improper value is given for --wfreq option

if (defined($wfreq) && ($wfreq <= 0 || $wfreq > 1)) {
  log_msg("err", "Please specify a positive real number not greater than 1 with --wfreq option");
  exit(1);
}

# exit if --readdump and --writedump options are used simultaneously

if (defined($readdump) && defined($writedump)) {
  log_msg("err", "--readdump and --writedump options can't be used together");
  exit(1);
}

# exit if --color option is given but no Term::ANSIColor module is installed

if (defined($color) && !$ansicoloravail) {
  log_msg("err", 
  "--color option requires Term::ANSIColor module which is not installed");
  exit(1);
}

# if --color option is given with a value, parse the value and set all
# colors to 'undef' which have not been provided in the value; 
# if --color option is given without a value, assume "green:red" 

if (defined($color)) { 
  if (length($color)) { 
    ($color1, $color2) = split(/:/, $color);
    if (!length($color1)) { $color1 = undef; }
    if (!length($color2)) { $color2 = undef; }
  } else {
    $color1 = "green";
    $color2 = "red";
  }
}

# if the --readdump option has been given, use the dump file for producing
# quick output without considering other command line options

if (defined($readdump)) {

  # read data from dump file into a buffer referenced by $ref

  my $ref = retrieve($readdump);

  # copy the data from buffer to %candidates and %fword_deps hash tables

  %candidates = %{$ref->{"Candidates"}};
  %fword_deps = %{$ref->{"FwordDeps"}};

  # since the data read from dump file has been copied to %candidates and
  # %fword_deps hash tables, free the memory that holds data from dump file

  $ref = undef;

  # if --wweight option has been given but no word dependency info
  # was found in dump file, exit with error

  if (defined($wweight) && scalar(keys %fword_deps) == 0) { 
    log_msg("err", "No word dependency information was found in dump file",
            $readdump, "which is required by --wweight option");
    exit(1);
  }

  # if --wweight option has been given, find the word weights for each 
  # candidate and join candidates

  if (defined($wweight)) {
    join_candidates();
  } else {
    %clusters = %candidates;
  }

  print_clusters();

  exit(0);
}

# check the support value

if (!defined($support) && !defined($rsupport)) {
  log_msg("err", "No support specified with --support or --rsupport option");
  exit(1);
}

if (defined($support) && defined($rsupport)) {
  log_msg("err", "--support and --rsupport options can't be used together");
  exit(1);
}

if (defined($support) && $support < 0) {
  log_msg("err", "Please specify non-negative integer with --support option");
  exit(1);
}

if (defined($rsupport) && ($rsupport < 0 || $rsupport > 100)) {
  log_msg("err", 
  "Please specify real number from the range 0..100 with --rsupport option");
  exit(1);
}

# evaluate input file patterns given in command line,
# and create the list of input files

foreach $fpat (@inputfilepat) {
  foreach $ifile (glob($fpat)) { $ifiles{$ifile} = 1; }
}

@inputfiles = keys %ifiles;

if (!scalar(@inputfiles)) {
  log_msg("err", "No input file(s) specified with --input option(s)");
  exit(1);
}

# compile the regular expression that matches word separator characters,
# and exit if the expression is invalid

if (!defined($separator)) { $separator = '\s+'; }
$sepregexp = eval { qr/$separator/ };

if ($@) {
  log_msg("err", 
    "Invalid regular expression $separator given with --separator option");
  exit(1);
}

# exit if --lfilter and --lcfunc options are used together

if (defined($lfilter) && defined($lcfunc)) {
  log_msg("err", "--lfilter and --lcfunc options can't be used together");
  exit(1);
}

# compile the line filtering regular expression,
# and exit if the expression is invalid

if (defined($lfilter)) {
  $lineregexp = eval { qr/$lfilter/ };
  if ($@) {
    log_msg("err", 
      "Invalid regular expression $lfilter given with --lfilter option");
    exit(1);
  }
}

# compile the line filter function, and exit if the compilation fails

if (defined($lcfunc)) {
  $lcfuncptr = compile_func_wrapper($lcfunc);
  if (!defined($lcfuncptr)) {
    log_msg("err", "Invalid function supplied with --lcfunc option");
    exit(1);
  }
}

# exit if --wfilter and --wcfunc options are used together

if (defined($wfilter) && defined($wcfunc)) {
  log_msg("err", "--wfilter and --wcfunc options can't be used together");
  exit(1);
}

# compile the word filtering regular expression, 
# and exit if the expression is invalid

if (defined($wfilter)) {
  $wordregexp = eval { qr/$wfilter/ };
  if ($@) {
    log_msg("err", 
      "Invalid regular expression $wfilter given with --wfilter option");
    exit(1);
  }
  if (!defined($wsearch)) { 
    log_msg("err", "--wfilter option requires --wsearch");
    exit(1);
  }
  $searchregexp = eval { qr/$wsearch/ };
  if ($@) {
    log_msg("err", 
      "Invalid regular expression $wsearch given with --wsearch option");
    exit(1);
  }
  if (!defined($wreplace)) { 
    log_msg("err", "--wfilter option requires --wreplace");
    exit(1);
  }
}

# compile the word class function, and exit if the compilation fails

if (defined($wcfunc)) {
  $wcfuncptr = compile_func_wrapper($wcfunc);
  if (!defined($wcfuncptr)) {
    log_msg("err", "Invalid function supplied with --wcfunc option");
    exit(1);
  }
}

# exit if improper value is given for --wsize option

if (defined($wsize) && $wsize < 1) {
  log_msg("err", "Please specify positive integer with --wsize option");
  exit(1);
}

# exit if improper value is given for --csize option

if (defined($csize) && $csize < 1) {
  log_msg("err", "Please specify positive integer with --csize option");
  exit(1);
}

# exit if --csize and --aggrsup options are used together

if (defined($csize) && defined($aggrsup)) {
  log_msg("err", "--csize and --aggrsup options can't be used together");
  exit(1);
}

##### start the clustering process #####

log_msg("info", "Starting the clustering process...");

# if the --wsize command line option has been given, make a pass over
# the data set and create the word sketch data structure @wsketch

if (defined($wsize)) { build_word_sketch(); }

# make a pass over the data set and find frequent words (words which appear 
# in $support or more lines), and store them to %fwords hash table

find_frequent_words();

# if the --wsize command line option has been given, release the word sketch

if (defined($wsize)) { @wsketch = (); }

# if the --csize command line option has been given, make a pass over
# the data set and create the candidate sketch data structure @csketch

if (defined($csize)) { build_candidate_sketch(); }

# make a pass over the data set and find cluster candidates; 
# if --wweight option has been given, dependencies between frequent 
# words are also identified during the data pass

find_candidates();

# if the --csize command line option has been given, release the candidate sketch

if (defined($csize)) { @csketch = (); }

# if --aggrsup option has been given, find more specific clusters for each
# cluster, and add supports of more specific clusters to the generic cluster

if (defined($aggrsup)) { 
  build_prefix_tree();
  aggregate_supports(); 
  $ptree = undef;
}

# find frequent candidates

find_frequent_candidates();

# store hash tables of candidates and frequent word dependencies to file

if (defined($writedump)) {
  store({ "Candidates" => \%candidates, 
          "FwordDeps" => \%fword_deps }, $writedump);
}

# if --wweight option has been given, find the word weights for each 
# candidate and join candidates

if (defined($wweight)) {
  join_candidates();
} else {
  %clusters = %candidates;
}

# report clusters

print_clusters();

# if --wweight option has been given, release word dependency hash table

if (defined($wweight)) { %fword_deps = (); }

# if --outliers option has been given, detect outliers

if (defined($outlierfile)) { find_outliers(); }

