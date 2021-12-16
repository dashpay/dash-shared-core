Pod::Spec.new do |s|
  s.name             = 'DashSharedCore'
  s.version          = '0.1.0'
  s.summary          = 'Dash Core written in Rust'
  s.author           = 'Dash'
  s.description      = "Dash Core"
  s.homepage         = 'https://github.com/dashevo/dash-shared-core'

  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.source           = { :git => 'https://github.com/dashevo/dash-shared-core.git', :tag => s.version.to_s }

  s.ios.deployment_target = '13.0'

  s.source_files = 'DashSharedCore/include/*'
  # s.public_header_files = 'Pod/Classes/**/*.h'

  s.prepare_command = <<-CMD
    ./build_pod.sh
  CMD

  s.ios.vendored_libraries = "DashSharedCore/lib/libinrustwetrust.a"
end